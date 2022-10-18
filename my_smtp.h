#ifndef MYSMTP
#define MYSMTP

#include <ctype.h>

#include "trameinfo.h"

/**
 * @brief Print the SMTP trame's info depance on verbose level into verbose buffer
 */
void PrintSMTP(const u_char *packect, struct trameinfo *trameinfo);

/**
 * @brief Decode the SMTP info since packet
 *  */
int DecodeSMTP(const u_char *packect, struct trameinfo *trameinfo);

#endif