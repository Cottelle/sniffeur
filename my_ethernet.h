#ifndef MY_ETH
#define MY_ETH

#include <stdio.h>
#include <net/ethernet.h>

#include "trameinfo.h"

#include "my_ip.h"
#include "my_arp.h"



/**
 * @brief Print the Ethernet trame's info depance on verbose level into the verbose buffer
 */
void VerboseEth(struct trameinfo* t);

/**
 * @brief Decode the Ethernet's info since packet
 */
int DecodeEthernet(const u_char *packet, struct trameinfo *trameinfo);



#endif