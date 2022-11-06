#include "my_ipv6.h"

void VerboseIP6(struct trameinfo *t)
{
    (void)t;
}

int DecodeIP6(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip6_hdr *ip6= (struct ip6_hdr *)packet;
    trameinfo->header_lv2 = (void *)ip6;
    trameinfo->Ipv = AF_INET6;

    trameinfo->cur+=sizeof(*ip6);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
    case 0X6:
        DecodeTCP(packet+sizeof(*ip6),trameinfo);
        break;
    
    default:
        DecodeUDP(packet+sizeof(*ip6),trameinfo);
        break;
    }

    return 0;
}