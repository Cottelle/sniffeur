#ifndef MYIP
#define MYIP

#include <netinet/ip.h>

#include "trameinfo.h"

#include "ip_protocol.h"
#include "my_tcp.h"
#include "my_udp.h"



/**
 * @brief manage the IP's option
 *
 */
void IPOption(void);

/**
 * @brief Print the IP's info depence of verbose level into verbose buffer
 */
void PrintIP(struct trameinfo *t);

/**
 * @brief Decode the IP's info since packet
 */
int DecodeIP(const u_char *packet, struct trameinfo *trameinfo);

#endif