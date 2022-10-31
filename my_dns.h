#ifndef MYDNS
#define MYDNS

#include "dns_apple.h"
#include "trameinfo.h"


// /**
//  * @brief Print the TCP flags 
//  */
// void PrintTCPFlags(uint8_t th_flags);

/**
 * @brief Print the TCP info depence of verbose level into verbose buffer
 */
void PrintDNS(struct trameinfo* t);

/**
 * @brief Decode TCP trame since packet
 */
int DecodeDNS(const u_char *packet, struct trameinfo *trameinfo);








#endif