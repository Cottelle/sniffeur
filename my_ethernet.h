#ifndef MY_ETH
#define MY_ETH

#include <stdio.h>
#include <net/ethernet.h>

#include "trameinfo.h"

#include "my_ip.h"

/**
 * @brief Convert a int into an physical addresse (char *). buf size must >17
 */
void INT2MAC(uint8_t *val, char *buf);

/**
 * @brief Print the Ethernet trame's info depance on verbose level into the verbose buffer
 */
void VerboseEth(struct trameinfo* t);

/**
 * @brief Decode the Ethernet's info since packet
 */
int DecodeEthernet(const u_char *packet, struct trameinfo *trameinfo);



#endif