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

    char buf[50]; //ON est large
    printf("%i and %s",ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt,inet_ntop(AF_INET6,(void *)&ip6->ip6_dst,buf,50));
    return 8;
}