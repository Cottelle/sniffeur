#ifndef TRAMEINFO
#define TRAMEINFO

#include <net/ethernet.h>

struct trameinfo
{
    int verbose;

    struct ether_header *eth_header;
    void * header_lv2;
    void * header_lv3;    //void * because we don't kwon the type of the header (IP ADR TCP UDP...)
    void * header_lv4; 

};


#endif