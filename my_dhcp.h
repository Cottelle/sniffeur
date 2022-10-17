#ifndef MYDHCP
#define MUDHCP

#include <string.h>

#include "trameinfo.h"


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


struct dhcp
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
 * @brief Print the DHCP trame's info depance on verbose level into verbose buffer
 */
void PrintDHCP(struct dhcp dhcps[64], struct trameinfo *t);

/**
 * @brief Decode the DCHP info after the magic cookie (pointed by vend)
 */
void DecodeDHCP(const u_char *vend, struct trameinfo *trameinfo); // a reprendre car vend[i] = en faite sais pas.



#endif