#ifndef UDP
#define UDP

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "analyseur.h"
// #include "trameinfo.h"


#define L_SRCPORT 16
#define L_DSTPORT 16
#define L_LGTH 16
#define L_SUM 16

struct udp
{
    unsigned int S_Port : L_SRCPORT;
    unsigned int D_Port : L_DSTPORT;
    unsigned int Length : L_LGTH;
    unsigned int Sum : L_SUM;
};
/**
 * @brief Transform the udp struct with the correct endien                                     < ----------------------------------------------------------
 */
void beSUDPtoh(struct udp *udp);

/**
 * @brief Print the UDP trame's info depance on verbose level  
 */
void PrintUDP(struct udp *udp, int verbose);

/**
 * @brief Decode the UDP's info since packet 
 */
int DecodeUDP(const u_char *packet, struct trameinfo *trameinfo);


#endif