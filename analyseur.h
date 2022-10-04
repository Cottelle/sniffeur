#ifndef ANALYSEUR
#define ANALYSEUR

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <bits/endian.h>

#include "my_ethernet.h"
#include "my_ip.h"
#include "my_tcp.h"
#include "udp.h"
#include "bootp.h"
#include "dhcp.h"

struct trameinfo
{
    int verbose;

    struct ether_header *eth_header;
    void * header_lv2;
    void * header_lv3;    //void * because we don't kwon the type of the header (IP ADR TCP UDP...)
    void * header_lv4; 

};


#endif