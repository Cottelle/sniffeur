#ifndef DHCP
#define DHCP

#include "analyseur.h"

#define SUBMASK 1
#define TIMEOFF 2
#define ROUTER 3
#define DNS    6
#define HOST 12
#define DOMAIN 15
#define BROCAST 28
#define NETSERV 44
#define NETSCOP 47
#define REQIP   50
#define LEASE   51
#define TYPE    53
#define SERVID  54
#define REQLIST 55
#define CID     61

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
void PrintDHCP(struct dhcps dhcps[64],int verbose);

/**
 * @brief Decode the DCHP info after the magic cookie (pointed by vend)
 */
void DecodeDHCP(const u_char *vend, struct trameinfo *trameinfo); // a reprendre car vend[i] = en faite sais pas.

#endif