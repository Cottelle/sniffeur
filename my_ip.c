#include "my_ip.h"

void IPOption(void)
{
    printf("There is option ??\n*");
}

void PrintIP(struct trameinfo *t)
{
    struct ip *ip = (struct ip *)t->header_lv2;

    if (t->verbose > 2)
        printf("\n");
    WriteInBuf(t, "|IP Decode : ");
    WriteInBuf(t, "Total length = %u, ", ip->ip_len);
    if (t->verbose > 2)
    {
        WriteInBuf(t, "IPv%u, Header length = %u*4 Bytes, ", ip->ip_v, ip->ip_hl);
        WriteInBuf(t, "Time to Live = %u,  Checksum = %x, ", ip->ip_ttl, ip->ip_sum);
    }
    if (ip->ip_hl > 5)
        if (t->verbose > 2)
            IPOption();

    if (t->verbose > 2)
        WriteInBuf(t, "There is no Option, ");
    switch (ip->ip_p)
    {
    case 0x06:
        WriteInBuf(t, "TCP Protocol");
        break;
    case 0x11:
        WriteInBuf(t, "UDP Protocol");
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

    trameinfo->cur+=ip->ip_hl*4;

    if (trameinfo->verbose > 1)
    {
        PrintIP(trameinfo);
    }

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
        break;
    }
    return 0;
}
