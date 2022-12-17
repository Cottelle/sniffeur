#include "my_ip.h"




void IPOption(void)
{
    printf("There is option ");
}

void VerboseIP(struct trameinfo *t)
{
    struct ip *ip = (struct ip *)t->header_lv2;

    WriteInBuf(t, "\n\t|IP : ");
    WriteInBuf(t, "Total length = %u, ", be16toh(ip->ip_len));
    if (t->verbose > 2)
    {
        WriteInBuf(t, "IPv%u, Header length = %u*4 Bytes, ", ip->ip_v, ip->ip_hl);
        WriteInBuf(t, "Time to Live = %u,  Checksum = %x, ", ip->ip_ttl, ip->ip_sum);
    }
    if (ip->ip_hl > 5)
        if (t->verbose > 2)
            IPOption();

    WriteInBuf(t,"Protocol = %s(%i)",(ip->ip_p< ROHC +1)? TabIpProtocol[ip->ip_p] :"",ip->ip_p);

    printf(" ");
}

int DecodeIP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip *ip = (struct ip *)packet;
    trameinfo->header_lv2 = (void *)packet;
    trameinfo->Ipv = AF_INET;

    trameinfo->cur += ip->ip_hl * 4;

    if (trameinfo->verbose > 1)
    {
        VerboseIP(trameinfo);
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
        printf("Unimplemeted Protocol %s (%x)   ", (ip->ip_p < ROHC + 1) ? TabIpProtocol[ip->ip_p] : "", ip->ip_p);
        break;
    }
    return 0;
}
