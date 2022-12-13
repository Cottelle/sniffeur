#ifndef MYHTTP
#define MYHTTP

#include <ctype.h>

#include "trameinfo.h"

/**
 * @brief Decode HTTP frame since packet
 *
 */
int DecodeHTTP(const u_char *packet, struct trameinfo *trameinfo);

#endif