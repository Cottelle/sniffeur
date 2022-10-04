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

#include "protocol.h"
#include "args-parser.h"


struct arg
{
    time_t starttime;
    int verbose;
    int Protocol;
    char **ip_src;
    char **ip_dest;
    char color;

    char Other_message[2048];
};




#endif