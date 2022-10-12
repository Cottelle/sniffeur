#include "my_tcp.h"
#include "analyseur.h"

void PrintTCP(struct tcphdr *tcphdr, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|Decode TCP: ");
    if (verbose > 2)
        printf("Checksum= %u, Urgent Pointeur= %u ", tcphdr->check, tcphdr->urg_ptr);
}




int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct tcphdr *tcphdr = (struct tcphdr *)packet;
    trameinfo->header_lv3 = (void *)packet;

    Synthese((struct ip *)trameinfo->header_lv2, tcphdr->th_sport, tcphdr->th_dport);

    printf(" seq= %u ack= %u win= %u ", be16toh(tcphdr->th_seq), be16toh(tcphdr->th_ack), tcphdr->th_win);

    if (trameinfo->verbose > 1)
    {
        PrintEth(trameinfo->eth_header, trameinfo->verbose);
        PrintIP((struct ip *)trameinfo->header_lv2, trameinfo->verbose);
        PrintTCP(tcphdr, trameinfo->verbose);
    }

    return 0;
}

