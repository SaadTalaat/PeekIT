#ifndef GLOBAL_STRUCTURES_H_
#define GLOBAL_STRUCTURES_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <netinet/tcp.h>
#define TH_OFF(th)      (((th)->doff & 0xf0) >> 4)
#define IP_HL(ip)              (((ip)->ip_hl) & 0x0f)
#define IP_QUAD(ip)  (ip)>>24,((ip)&0x00ff0000)>>16,((ip)&0x0000ff00)>>8,((ip)&0x000000ff)
#define IP_ADDR_LEN	4
struct ip
  {
#if WORDS_BIGENDIAN
    u_int8_t ip_v:4;                    /* version */
    u_int8_t ip_hl:4;                   /* header length */
#else
    u_int8_t ip_hl:4;                   /* header length */
    u_int8_t ip_v:4;                    /* version */ 
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };
#define ETHER_SIZE 14

struct {
	char *dev;
	int sd;
	struct ether_addr eth;
	struct in_addr ip;
	struct in_addr bcast;
	unsigned int mtu;
} local_info ;

struct {
	struct pcap_pkthdr curr_hdr;
	u_int32_t pkt_len;
	struct timeval rec_time;
} remote_info;
struct {
	u_char *packet;
	u_int16_t packet_type;
	u_int8_t *dhost;
	u_int8_t *shost;
	u_int8_t *dhost_ip;
	u_int8_t *shost_ip;
} packet_info;
char *help = "Usage: peekit -i <device> -c <Packet No.> -g <gateway address> -s <server address>\n\t-i\tNetwork interface card (e.g. eth0 em0 wlan0)\n\t-c\tNumber of packets to be grabbed\n\t-g\tGteway address\n\t-s\tServer Address\nBy Saad Talaat (saadtalaat@gmail.com)\n";
#endif /* GLOBAL_STRUCTURES_H_ */
