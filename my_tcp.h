#ifndef MYTCP
#define MYTCP

#include <netinet/tcp.h>

#include "trameinfo.h"
#include "my_smtp.h"
#include "my_telnet.h"
#include "my_http.h"
#include "my_pop3.h"


/**
 * @brief Print the TCP flags 
 */
void PrintTCPFlags(uint8_t th_flags);

/**
 * @brief Print the TCP info depence of verbose level into verbose buffer
 */
void VerboseTCP(struct trameinfo* t);

/**
 * @brief Decode TCP trame since packet
 */
int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo);








#endif