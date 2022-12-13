#ifndef MYSMTP
#define MYSMTP

#include <ctype.h>

#include "trameinfo.h"


/**
 * @brief Decode the SMTP info since packet
 *  */
int DecodeSMTP(const u_char *packect, struct trameinfo *trameinfo);

#endif