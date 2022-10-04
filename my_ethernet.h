
#ifndef MYETHERNET
#define MYETHERNET

#include "analyseur.h"
// #include "trameinfo.h"

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



#endif