#include "my_ipv6.h"



void VerboseIP6(struct trameinfo *t)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)t->header_lv2;
    WriteInBuf(t, "\n\t|Decode IPv6 :");
    if (t->verbose > 2)
        WriteInBuf(t, "Verion= %i, Trafic= %i, Flow= %i", (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & 0xf0) >> 4, (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xff0f, be16toh(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow >> 16));
    WriteInBuf(t, "Lenght= %i, Next= %s(%i)", ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt < ROHC + 1) ? TabIpProtocol[ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt] : "", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    if (t->verbose>2)
        WriteInBuf(t,", Hop limit= %i",ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
}

int DecodeIP6(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
    trameinfo->header_lv2 = (void *)ip6;
    trameinfo->Ipv = AF_INET6;

    trameinfo->cur += sizeof(*ip6);

    if (trameinfo->verbose > 1)
        VerboseIP6(trameinfo);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
    case 0X6:
        DecodeTCP(packet + sizeof(*ip6), trameinfo);
        break;

    case 0x11:
        DecodeUDP(packet + sizeof(*ip6), trameinfo);
        break;
    default:
        printf("Unreconized Protocol %i", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        break;
    }

    return 0;
}