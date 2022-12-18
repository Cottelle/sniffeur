#ifndef TRAMEINFO
#define TRAMEINFO

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <netinet/ip.h> //For Synthèse
#include <netinet/ip6.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_protocol.h"


extern char *GREEN;
extern char *BLUE;
extern char *RED ;
extern char *YELLOW;
extern char *MAGENTA;
extern char *CYAN;
extern char *WHITE;
extern char *BLACK;
extern char *RESET;

extern char TabIpProtocol[143][20];



struct trameinfo
{
    const u_char* packet;
    uint len;         //The len of the trame
    uint cur;         //The current place

    int verbose;     //verbose value (1 = low | 2 = meduim | 3  = high (|4 + = debug))

    int Ipv;           // The ip versions (can be unused)  
    struct ether_header *eth_header;
    void *header_lv2;
    void *header_lv3; // void * because we don't kwon the type of the header (IP ADR TCP UDP...)
    void *header_lv4;

    char *bufverbose; // the buffer where the additional info are put, print a the end of the parsing
    int size_buf;     // the dynamic size of the buf
    int write_buf;    // the start of d place on this buf


};


/* Usefull function for many protocol*/

/**
 * @brief Convert a int into an physical addresse (char *). And return buf for easy print. buf size must >17
 */
char *INT2MAC(uint8_t *val, char *buf);

/**
 * @brief Write a the format in the bufverbose (into trameinfo). This function handle memory size
 */
void WriteInBuf(struct trameinfo *trameinfo, char *format, ...);



/**
 * @brief Print major info of the current trame with the ip and port. Use with IP protocol to show  unsincronized info (IP Port IP Port)
 */
void SyntheseIP(struct trameinfo *t, int SP, int DP);

/**
 * @brief Same but without port (fort uncomplete decode)
 */
void SyntheseIPU(struct trameinfo *t);

#endif