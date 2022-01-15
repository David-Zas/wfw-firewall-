#include "conf.h"
#include "hash.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Constantss */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define PID       "pidfile"
#define IPV6TYPE  0x86DD

/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;
static bool foreground = false;

//eframe structure
struct frame_t {
  uint8_t dst [6];
  uint8_t src [6];
  uint16_t type;
  uint8_t data[1500];
};

//IPv6 packet structure
typedef 
struct ipv6_head {
  uint32_t vers       : 4;
  uint32_t tfcClass   : 8;
  uint32_t flabel     : 20;
  
  uint32_t payloadLen : 16;
  uint32_t nxtHdr     : 8;
  uint32_t hopLimit   : 8;

  uint8_t srcAddr[16];
  uint8_t dstAddr[16];

  uint8_t nxtHdrs[];
  
}ipv6head_t;

//tcpsegment structure
typedef
struct segment{
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seqNum;
  uint32_t ackNum;

  uint16_t          : 4;
  uint16_t hdrsz    : 4;
  uint16_t FIN      : 1;
  uint16_t SYN      : 1;
  uint16_t RST      : 1;
  uint16_t PSH      : 1;
  uint16_t ACK      : 1;
  uint16_t URG      : 1;
  uint16_t          : 2;

  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
  uint32_t options[];
}tcpsegment_t;

//key structure
typedef
struct tcpkey{ 
  uint16_t localPort;   
  uint16_t remotePort;
  uint8_t remoteIPaddr[16];
}tcpkey_t;

/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseoptions(int argc, char* argv[]);

/* Usage
 * cmd   The name by which this program was invoked
 * file  The steam to which the usage statement is printed
 *
 * This function prints the simple usage statement.  This is typically invoked
 * if the user provides -h on the command line or the options don't parse.  
 */
static
void usage(char* cmd, FILE* file);

/* Ensure Tap
 * path     The full path to the tap device.
 * returns  If this function returns, it is the file descriptor for the tap
 *          device. 
 * 
 * This function tires to open the specified device for reading and writing.  If
 * that open fails, this function will report the error to stderr and exit the
 * program.   
 */
static
int  ensuretap(char* path);

/* Ensure Socket
 * localaddress   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensuresocket(char* localaddr, char* port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makesockaddr(char* address, char* port);

/* mkfdset
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkfdset(fd_set* set, ...);

/* Key Value free 
 *
 * Memory management for the hash table buckets.  
 * NOTE: directly copied from conf.c
 */
static
void kvfree(void* key, void* value);

/*
 *addrcmp
 *  - helper function to help make the hashtable
 *  Takes 2 keys and runs a memcmp() on them then returns that value.
 *  RETURNS: 0 if the keys are the same and anything else if not
 */
 static int addrcmp(void *key, void *key2);

/*
 *ipv6cmp
 */
 static int ipv6cmp(void *key, void *key2);

/*
 *BLaddrcmp
 *  - helper function to help make the hashtable
 *  Takes 2 keys and runs a memcmp() on them then returns that value.
 *  RETURNS: 0 if the keys are the same and anything else if not
 */
 static int BLaddrcmp(void *key, void *key2);

/*
*filter
* filters out the adresses with the mac 0xff && 0x33
* RETURNS: true when the src does not match any unwanted addresses and false when it does
*/
static 
bool filter(unsigned char *src);

/*
 *isIpv6
 * RETURNS: true if ipvs type, and false if otherwise
 */
static
bool isIpv6(uint16_t type);

/*
* IPV6CHECK******************************************edit******************
* checks if type field on eframe equals the ipv6 type
* RETURNS: true if ipv6, false if not
*/
static
bool IPV6CHECK(uint16_t type);

/*
 *blackListed
 * 
 */
static
bool blackListed(hashtable *blackList, struct frame_t *buffer);

/*
 * sendPack
 * RETURNS: false if not in the ipv6ht and is a "valid" ipv6 packet, true if otherwise
 */
static 
bool sendPack(hashtable *ipv6ht, hashtable *blackList, struct frame_t *buffer);

/*
 *acceptInput
 * Takes input from in or out device from bridge func then processes
 * and maps that information to a hashtable
 */
static 
void 
acceptInput(int input, struct frame_t *buffer, int tap, hashtable *yellowPages, hashtable *blackList, hashtable *ipv6ht);

/*
 * ipv6insert
 *      inserts frame into ipv6 ht if communication has been established by wfw
 * 
 */
static
void ipv6insert(hashtable *ipv6ht, struct frame_t frame);

/* Bridge 
 * tap     The local tap device
 * in      The network socket that receives broadcast packets.
 * out     The network socket on with to send broadcast packets.
 * bcaddr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr);

/* daemonize
 *
 * 
 * Make this process a background, daemon process.
 */
static
void daemonize(hashtable conf); 

/* Main
 * 
 * Mostly, main parses the command line, the conf file, creates the necessary
 * structures and then calls bridge.  Bridge is where the real work is done. 
 */
int main(int argc, char* argv[]) {
  int result = EXIT_SUCCESS;

  if(!parseoptions(argc, argv)) {
    usage(argv[0], stderr);
    result = EXIT_FAILURE;
  }
  else if(printusage) {
    usage(argv[0], stdout);
  }
  else {
    hashtable conf = readconf (conffile);
    int       tap  = ensuretap (htstrfind (conf, DEVICE));
    int       out  = ensuresocket(ANYIF, ANYPORT);
    int       in   = ensuresocket(htstrfind (conf, BROADCAST),
                                  htstrfind (conf, PORT));
    struct sockaddr_in
      bcaddr       = makesockaddr (htstrfind (conf,BROADCAST),
                                   htstrfind (conf, PORT));
    
    if(!foreground){
      daemonize(conf);
    }
    bridge(tap, in, out, bcaddr);
    
    close(in);
    close(out);
    close(tap);
    htfree(conf);
  }

  return result;
}

/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseoptions(int argc, char* argv[]) {
  static const char* OPTS = "hc:f";

  bool parsed = true;

  char c = getopt(argc, argv, OPTS);
  while(c != -1) {
    switch (c) {
    case 'c':
      conffile = optarg;
      break;
        
    case 'h':
      printusage = true;
      break;

    case 'f':
      foreground = true;
      break;

    case '?':
      parsed = false;
      break;
    }

    c = parsed ? getopt(argc, argv, OPTS) : -1;
  }

  if(parsed) {
    argc -= optind;
    argv += optind;
  }

  return parsed;
}

/* Print Usage Statement
 *
 */

static
void usage(char* cmd, FILE* file) {
  fprintf(file, "Usage: %s -c file.cfg [-h]\n", cmd);
}

/* Ensure Tap device is open.
 *
 */
static
int ensuretap(char* path) {
  int fd = open(path, O_RDWR | O_NOSIGPIPE);
  if(-1 == fd) {
    perror("open");
    fprintf(stderr, "Failed to open device %s\n", path);
    exit(EXIT_FAILURE);
  }
  return fd;
}

/* Ensure socket
 *
 * Note the use of atoi, htons, and inet_pton. 
 */
static
int ensuresocket(char* localaddr, char* port) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if(-1 == sock) {
    perror("socket");
    exit (EXIT_FAILURE);
  }

  int bcast = 1;
  if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       &bcast, sizeof(bcast))) {
    perror("setsockopt(broadcast)");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = makesockaddr(localaddr, port);
  if(0 != bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind");
    char buf[80];
    fprintf(stderr,
            "failed to bind to %s\n",
            inet_ntop(AF_INET, &(addr.sin_addr), buf, 80));
    exit(EXIT_FAILURE);
  }

  return sock;  
}

/* Make Sock Addr
 * 
 * Note the use of inet_pton and htons.
 */
static
struct sockaddr_in makesockaddr(char* address, char* port) {
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_len    = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(atoi(port));
  inet_pton(AF_INET, address, &(addr.sin_addr));

  return addr;
}

/* mkfdset
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkfdset(fd_set* set, ...) {
  int max = 0;
  
  FD_ZERO(set);
  
  va_list ap;
  va_start(ap, set);
  int s = va_arg(ap, int);
  while(s != 0) {
    if(s > max)
      max = s;
    FD_SET(s, set);
    s = va_arg(ap, int);
  }
  va_end(ap);
  
  return max;
}

/* Key Value free 
 *
 * Memory management for the hash table buckets.  
 * NOTE: directly copied from conf.c
 */
static
void kvfree(void* key, void* value) {
  free(key);
  free(value);
}

/*
 *addrcmp
 *  - helper function to help make the hashtable
 *  Takes 2 keys and runs a memcmp() on them then returns that value.
 *  RETURNS: 0 if the keys are the same and anything else if not
 */
 static int addrcmp(void *key, void *key2){
    int diff = memcmp(key,key2,6);
    return diff;
 } 

/*
 *ipv6cmp
 */
 static int ipv6cmp(void *key, void *key2){
    int diff = memcmp(key,key2,sizeof(tcpkey_t));
    return diff;
 } 

/*
 *BLaddrcmp
 *  - helper function to help make the hashtable
 *  Takes 2 keys and runs a memcmp() on them then returns that value.
 *  RETURNS: 0 if the keys are the same and anything else if not
 */
 static int BLaddrcmp(void *key, void *key2){
    return memcmp(key,key2,16);
 } 

/*
*filter
* filters out the adresses with the mac 0xff && 0x33
* RETURNS: true when the src does not match any unwanted addresses and false when it does
* 
*/
static bool filter(unsigned char *src){
  static const uint8_t f1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  static const uint8_t f2[] = {0x33, 0x33};

  return (memcmp(src, &f1, 6) != 0 && memcmp(src, &f2, 2) != 0);
}

/*
 *isIpv6
 * checks if type field on frame equals the ipv6 type
 * RETURNS: true if ipv6 type, false if any other type
 */
static
bool isIpv6(uint16_t type){
  return (type == IPV6TYPE);
}

/*
* IPV6CHECK******************************************edit******************
* checks if type field on eframe equals the ipv6 type
* RETURNS: true if ipv6, false if not
*/
static
bool IPV6CHECK(uint16_t type){
  return memcmp(type, IPV6TYPE, 16);

}

/*
 *blackListed
 * checks if an e frame has been blacklisted by wfw
 * RETURNS: true if it is blacklisted and false if it is not
 */
static
bool blackListed(hashtable *blackList, struct frame_t *buffer){
  ipv6head_t *head = (ipv6head_t*)buffer->data;
  return hthaskey(*blackList, head->dstAddr, 16);
}

/*
 * sendPack
 * RETURNS: true if not IPV6 type || IPV6 type and a connection has already been established
 */
static 
bool sendPack(hashtable *ipv6ht, hashtable *blackList, struct frame_t *buffer){
  bool sendFlag = false;

  if(!blackListed(blackList, buffer)){
    uint16_t type = htons(buffer->type);
    
    if(isIpv6(type)){
      ipv6head_t *head = (ipv6head_t*)buffer->data;
      if(head->nxtHdr == 6){   
        tcpsegment_t *tcpseg = (tcpsegment_t*)head->nxtHdrs;

        tcpkey_t key;
        memcpy(&key.localPort, &tcpseg->dstPort, 2);
        memcpy(&key.remotePort, &tcpseg->srcPort, 2);
        memcpy(&key.remoteIPaddr, &head->srcAddr, 16);

        if(!hthaskey(*ipv6ht, &key, sizeof(tcpkey_t))){
          unsigned char *badActor = malloc(16);
          memcpy(badActor, &head->srcAddr, 16);
          htinsert(*blackList, badActor, 16, NULL);
          /*   TEST   */
          /*printf("Blacklisted ");
                for (int i = 0; i < 16; ++i) {
                    printf("%x", badActor[i]);
                }
          printf("\n \n");
          /*   TEST   */
        }else{
          sendFlag = true;
        }
      }
    }else{
      sendFlag = true;
    }
  }
  return sendFlag;
}

/*
 *acceptInput
 * Takes input from in or out device from bridge func then processes
 * and maps that information to a hashtable
 */
static 
void 
acceptInput(int input, struct frame_t *buffer, int tap, hashtable *yellowPages, hashtable *blackList, hashtable *ipv6ht){
  struct sockaddr_in from;
  socklen_t          flen = sizeof(from);
  ssize_t rdct = recvfrom(input, buffer, sizeof(struct frame_t), 0, 
                          (struct sockaddr*)&from, &flen);
  if(rdct < 0) {
    perror("recvfrom");

  }else{ 
    if(sendPack(ipv6ht, blackList, buffer)){
      if(filter(buffer->dst)){
        if(!hthaskey(*yellowPages, buffer->src, sizeof(6))){ 
          struct sockaddr_in *value = malloc(sizeof(struct sockaddr_in));
          memcpy(value, &from, sizeof(struct sockaddr_in));

          char* srcmac = malloc(6);
          memcpy(srcmac, buffer->src, 6);

          htinsert(*yellowPages, srcmac, sizeof(6), value);

          }else{  
          struct sockaddr_in *value = htfind(*yellowPages, buffer->src, sizeof(6));
          memcpy(value, &from, sizeof(struct sockaddr_in));
          }  
      }
      if(-1 == write(tap, buffer, rdct)){
        perror("write");
      }
    }
  }
}

/*
 * ipv6insert
 *      inserts frame into ipv6 ht if communication has been established by wfw
 * 
 */
static
void ipv6insert(hashtable *ipv6ht, struct frame_t frame){
  uint16_t type = htons((&frame)->type);
  if(isIpv6(type)){ 
    ipv6head_t *head = (ipv6head_t*)(&frame)->data;

    if(head->nxtHdr == 6){   
      tcpsegment_t *tcpseg = (tcpsegment_t*)head->nxtHdrs;

      if(tcpseg->SYN != 0){
        tcpkey_t *key = malloc(sizeof(tcpkey_t));
        memcpy(&key->localPort, &tcpseg->srcPort, 2);
        memcpy(&key->remotePort, &tcpseg->dstPort, 2);
        memcpy(&key->remoteIPaddr, head->dstAddr, 16); 

        if(!hthaskey(*ipv6ht, key, sizeof(tcpkey_t))){  
          htinsert(*ipv6ht, key, sizeof(tcpkey_t), NULL);   
        }
      }
    }
  }
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom. 
 * NOTE: Creates a hashtable (yellowPages) to keep track of devices connecting to wfw 
 *       and a hashtable (ipv6ht) to keep track of ipv6 communications that have been 
 *       established
 */ 
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr) {
  hashtable yellowPages = htnew(75, (keycomp)addrcmp, kvfree); 
  hashtable ipv6ht = htnew(49, (keycomp)ipv6cmp, kvfree);
  hashtable blackList = htnew(100, (keycomp)BLaddrcmp, kvfree);    

  fd_set rdset;

  int maxfd = mkfdset(&rdset, tap, in, out, 0);

  struct frame_t frame;
  
  while(0 <= select(1+maxfd, &rdset, NULL, NULL, NULL)) {
    if(FD_ISSET(tap, &rdset)) {
      ssize_t rdct = read(tap, &frame, sizeof(struct frame_t));
      if(rdct < 0) {
          perror("read");
      }else{    
        ipv6insert(&ipv6ht, frame);

        struct sockaddr_in *sock;
        if(hthaskey(yellowPages, frame.dst, sizeof(frame.dst))){
          sock = htfind(yellowPages, frame.dst, sizeof(frame.dst));
        }else{
          sock = &bcaddr;
        }


        if(-1 == sendto(out, &frame, rdct, 0, (struct sockaddr*)sock, sizeof(bcaddr))){
          perror("sendto");
        }      
      }
    }
    else if(FD_ISSET(in, &rdset)) {
      acceptInput(in, &frame, tap, &yellowPages, &blackList, &ipv6ht);
    
    }else if(FD_ISSET(out, &rdset)){
      acceptInput(out, &frame, tap, &yellowPages, &blackList, &ipv6ht);
    }
    
    maxfd = mkfdset(&rdset, tap, in, out, 0);
  }
  htfree(yellowPages);
}

/* daemonize
 * Make this process a background, daemon process.
 */
static
void daemonize(hashtable conf){
  daemon(0,0);
  if(hthasstrkey(conf, PID)){
    FILE* pidfile = fopen(htstrfind(conf, PID), "w");
    if(pidfile != NULL){
      fprintf(pidfile, "%d\n", getpid());
      fclose(pidfile);
    }
  } 
}
