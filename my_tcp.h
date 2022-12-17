#ifndef MYTCP
#define MYTCP

#include <netinet/tcp.h>

#include "trameinfo.h"
#include "my_smtp.h"
#include "my_telnet.h"
#include "my_http.h"
#include "my_pop3.h"
#include "my_ftp.h"

/**
 * @brief Decode TCP trame since packet
 */
int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo);








#endif