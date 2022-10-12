
#include "my_ip.h"
#include "trameinfo.h"

void IPOption(void)
{
    printf("There is option ??\n*");
}


void PrintIP(struct ip *ip, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|IP Decode : ");
    printf("Total length = %u, ", ip->ip_len);
    if (verbose > 2)
    {
        printf("IPv%u, Header length = %u*4 Bytes, ", ip->ip_v, ip->ip_hl);
        printf("Time to Live = %u,  Checksum = %x, ", ip->ip_ttl, ip->ip_sum);
    }
    if (ip->ip_hl > 5)
        if (verbose > 2)
            IPOption();

    if (verbose > 2)
        printf("There is no Option, ");
    switch (ip->ip_p)
    {
    case 0x06:
        printf("TCP Protocol");
        break;
    case 0x11:
        printf("UDP Protocol");
        break;
    default:
        break;
    }
    printf(" ");
}


int DecodeIP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip *ip = (struct ip *)packet;
    trameinfo->header_lv2 = (void *)packet;

    if (ip->ip_hl > 5)
        IPOption();

    switch (ip->ip_p)
    {
    case 0x06:
        DecodeTCP(packet + 4 * ip->ip_hl, trameinfo);
        break;
    case 0x11:
        DecodeUDP(packet + 4 * ip->ip_hl, trameinfo);
        break;
    default:
        printf("Unreconized Protocol (%x)   ", ip->ip_p);
        if (trameinfo->verbose > 1)
        {
            PrintEth(trameinfo->eth_header, trameinfo->verbose);
            PrintIP(ip, trameinfo->verbose);
        }
        break;
    }
    return 0;
}

