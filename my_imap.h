#ifndef MYIMAP
#define MYIMAP

#include <ctype.h>

#include "trameinfo.h"

/**
 * @brief Decode IMAP frame since packet
 *
 */
int DecodeIMAP(const u_char *packet, struct trameinfo *trameinfo);

#endif