#ifndef MYIP
#define MYIP

#include <netinet/ip.h>

#include "trameinfo.h"

#include "ip_protocol.h"
#include "my_tcp.h"
#include "my_udp.h"



/**
 * @brief Decode the IP's info since packet
 */
int DecodeIP(const u_char *packet, struct trameinfo *trameinfo);

#endif