#ifndef MYTCP
#define MYTCP

#include <netinet/tcp.h>

#include "trameinfo.h"

/**
 * @brief Print the TCP info depence of verbose level into verbose buffer
 */
void PrintTCP(struct trameinfo* t);

/**
 * @brief Decode TCP trame since packet
 */
int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo);








#endif