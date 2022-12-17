#ifndef MYIPV6
#define MYIPV6

#include <netinet/ip6.h>

#include "trameinfo.h"
#include "my_tcp.h"
#include "my_udp.h"
#include "ip_protocol.h"


/**
 * @brief Decode the IP6's info since packet
 */
int DecodeIP6(const u_char *packet, struct trameinfo *trameinfo);

#endif