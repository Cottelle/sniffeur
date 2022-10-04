#ifndef MYTCP
#define MYTCP

#include "analyseur.h"


/**
 * @brief Print the TCP info depence of verbose level 
 */
void PrintTCP(struct tcphdr *tcphdr, int verbose);

/**
 * @brief Decode TCP trame since packet
 */
int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo);


#endif