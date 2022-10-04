#ifndef MYIP
#define MYIP

#include "analyseur.h"

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



#endif
