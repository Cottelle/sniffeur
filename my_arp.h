#ifndef MYARP
#define MYARP

#include <net/if_arp.h>
#include "trameinfo.h"

struct arp
{ // struct find on internet https://gist.github.com/ardikars/bfcbdef7e37deda0e797 modify
    unsigned short int hw_type;
    unsigned short int pro_type;
    unsigned char hw_len;
    unsigned char pro_len;
    unsigned short int op;
    unsigned char sha[6];
    unsigned char spa[4];
    unsigned char tha[6];
    unsigned char tpa[4];

    struct in_addr *sp,*tp;     //We can't put struct in_addr in the cast up because unsigned char is smaller then struct in_addr
};

/**
 * @brief Decode the ARP info since packet
 *  */
int DecodeARP(const u_char *packect, struct trameinfo *trameinfo);

#endif
