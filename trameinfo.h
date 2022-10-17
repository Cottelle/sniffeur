#ifndef TRAMEINFO
#define TRAMEINFO

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <netinet/ip.h> //For Synthèse
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BLACK(op) 30 * (op)
#define RED(op) 31 * (op)
#define GREEN(op) 32 * (op)
#define YELLOW(op) 33 * (op)
#define BLUE(op) 34 * (op)
#define MAGENTA(op) 35 * (op)
#define CYAN(op) 36 * (op)
#define WHITE(op) 37 * (op)

struct trameinfo
{
    int verbose;
    char color;
    struct ether_header *eth_header;
    void *header_lv2;
    void *header_lv3; // void * because we don't kwon the type of the header (IP ADR TCP UDP...)
    void *header_lv4;

    char *bufverbose; // the buffer where the additional info are put, print a the end of the parsing
    int size_buf;     // the dynamic size of the buf
    int write_buf;    // the start of free place on this buf
};

/**
 * @brief Convert a int into an physical addresse (char *). And return buf for easy print. buf size must >17
 */
char *INT2MAC(uint8_t *val, char *buf);

/**
 * @brief Write a the foramt in the bufverbose
 */
void WriteInBuf(struct trameinfo *trameinfo, char *format, ...);

/**
 * @brief Print major info of the current trame with the ip and port. Color is a bool indicate if the text is will colored. Use with IP protocol to show  unsincronized info (IP Port IP Port)
 */
void SyntheseIP(struct ip *ip, int SP, int DP, char color);

#endif