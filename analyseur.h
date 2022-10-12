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

void Synthese(struct ip *ip, int SP, int DP);



#endif