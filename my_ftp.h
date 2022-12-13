#ifndef MYFTP
#define MYFTP

#include <ctype.h>

#include "trameinfo.h"

/**
 * @brief Decode FTP frame since packet, list is if it is listening mode (21)
 *
 */
int DecodeFTP(const u_char *packet, struct trameinfo *trameinfo,int list);

#endif