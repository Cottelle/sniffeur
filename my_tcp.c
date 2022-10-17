#include "my_tcp.h"




void PrintTCP(struct trameinfo *t)
{

    struct tcphdr *tcphdr = (struct tcphdr *)t->header_lv3;
    if (t->verbose > 2)
        WriteInBuf(t,"\n");
    WriteInBuf(t,"|Decode TCP: ");
    if (t->verbose > 2)
        WriteInBuf(t,"Checksum= %u, Urgent Pointeur= %u ", tcphdr->check, tcphdr->urg_ptr);
}

int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct tcphdr *tcphdr = (struct tcphdr *)packet;
    trameinfo->header_lv3 = (void *)packet;

    if (trameinfo->verbose > 1)
        PrintTCP(trameinfo);

    SyntheseIP((struct ip *)trameinfo->header_lv2, tcphdr->th_sport, tcphdr->th_dport, trameinfo->color);

    printf(" seq= %u ack= %u win= %u ", be16toh(tcphdr->th_seq), be16toh(tcphdr->th_ack), tcphdr->th_win);


    return 0;
}
