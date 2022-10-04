/* On aurait préferer faire un .h pour chaque Protocol mais cela fait des include croisé (cf git Proto_dif_files)*/
#ifndef PROTOCOL
#define PROTOCOL

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <bits/endian.h>
#include <string.h>

#define BLACK(op) 30*(op)
#define RED(op) 31*(op)
#define GREEN(op) 32*(op)
#define YELLOW(op) 33*(op)
#define BLUE(op) 34*(op)
#define MAGENTA(op) 35*(op)
#define CYAN(op) 36*(op)
#define WHITE(op) 37*(op)



struct trameinfo
{
    int verbose;
    char color;
    struct ether_header *eth_header;
    void *header_lv2;
    void *header_lv3; // void * because we don't kwon the type of the header (IP ADR TCP UDP...)
    void *header_lv4;
};


/**
 * @brief Print major info of the current trame with the ip and port. Color is a bool indicate if the text is will colored
 */
void Synthese(struct ip *ip, int SP, int DP,char color);

/* ---------------------------------------------------------bootp--------------------------------------------------------------------------------------
 */

#define HEADER_LEN 44 // Octet
#define SNAME_LEN 64  // Octet
#define FILE_LEN 128  // Octet
// vend has no size beaucause it can be extended

struct bootp
{
    unsigned char op : 8;
    unsigned char htype : 8;
    unsigned char hlen : 8;
    unsigned char hops : 8;

    unsigned int xid : 32;

    unsigned int secs : 16;
    unsigned int flags : 16;

    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    unsigned int chaddr[16];

    const u_char *sname;
    const u_char *file;
    const uint16_t *vend;
};

/**
 * @brief Print the Bootp info depence of verbose level
 */
void PrintBootp(struct bootp *bootp, int verbose);

/**
 * @brief Decode Bootp trame since packet
 */
int DecodeBootp(const u_char *packet, struct trameinfo *trameinfo);

/* ---------------------------------------------------------dhcp--------------------------------------------------------------------------------------
 */

#define SUBMASK 1
#define TIMEOFF 2
#define ROUTER 3
#define DNS 6
#define HOST 12
#define DOMAIN 15
#define BROCAST 28
#define NETSERV 44
#define NETSCOP 47
#define REQIP 50
#define LEASE 51
#define TYPE 53
#define SERVID 54
#define REQLIST 55
#define CID 61

// struct dhcp
// {
//     struct in_addr *subnet_mask;
//     struct in_addr *router;
//     char **timeoff;
//     struct in_addr **dns;
//     char **host_name;
//     char **domain_name;
//     struct in_addr brocast_addr;
//     int netbios_name_server;
//     int netbios_scope;
//     struct in_addr requested_ip;
//     int lease_time;
//     char DHCP_type;
//     struct in_addr *server_id;
//     char **request_list;
//     char **client_id;

// };

struct dhcps
{
    char present;
    char size;
    const u_char *str;
};

/**
 * @brief Resolve DHCP's names code
 */
void DHCPnames_reso(int code, char *buf);

/**
 * @brief Print the DHCP trame's info depance on verbose level
 */
void PrintDHCP(struct dhcps dhcps[64], int verbose);

/**
 * @brief Decode the DCHP info after the magic cookie (pointed by vend)
 */
void DecodeDHCP(const u_char *vend, struct trameinfo *trameinfo); // a reprendre car vend[i] = en faite sais pas.

/* ---------------------------------------------------------ethernet--------------------------------------------------------------------------------------
 */

/**
 * @brief Convert a int into an physical addresse (char *). buf size must >17
 */
void INT2MAC(uint8_t *val, char *buf);

/**
 * @brief Print the Ethernet trame's info depance on verbose level
 */
void PrintEth(struct ether_header *ether_header, int verbose);

/**
 * @brief Decode the Ethernet's info since packet
 */
int DecodeEthernet(const u_char *packet, struct trameinfo *trameinfo);

/* ---------------------------------------------------------ip--------------------------------------------------------------------------------------
 */

/**
 * @brief manage the IP's option
 *
 */
void IPOption(void);

/**
 * @brief Print the IP's info depence of verbose level
 */
void PrintIP(struct ip *ip, int verbose);

/**
 * @brief Decode the IP's info since packet
 */
int DecodeIP(const u_char *packet, struct trameinfo *trameinfo);

/* ---------------------------------------------------------tcp--------------------------------------------------------------------------------------
 */

/**
 * @brief Print the TCP info depence of verbose level
 */
void PrintTCP(struct tcphdr *tcphdr, int verbose);

/**
 * @brief Decode TCP trame since packet
 */
int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo);

/* ---------------------------------------------------------udp--------------------------------------------------------------------------------------
 */

#define L_SRCPORT 16
#define L_DSTPORT 16
#define L_LGTH 16
#define L_SUM 16

struct udp
{
    unsigned int S_Port : L_SRCPORT;
    unsigned int D_Port : L_DSTPORT;
    unsigned int Length : L_LGTH;
    unsigned int Sum : L_SUM;
};
/**
 * @brief Transform the udp struct with the correct endien                                     < ----------------------------------------------------------
 */
void beSUDPtoh(struct udp *udp);

/**
 * @brief Print the UDP trame's info depance on verbose level
 */
void PrintUDP(struct udp *udp, int verbose);

/**
 * @brief Decode the UDP's info since packet
 */
int DecodeUDP(const u_char *packet, struct trameinfo *trameinfo);

#endif