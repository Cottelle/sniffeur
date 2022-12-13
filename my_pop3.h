#ifndef MYPOP3
#define MYPOP3

#include <ctype.h>

#include "trameinfo.h"

/**
 * @brief Decode POP3 frame since packet
 *
 */
int DecodePOP3(const u_char *packet, struct trameinfo *trameinfo);

#endif