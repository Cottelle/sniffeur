#include "my_tcp.h"

void PrintTCPFlags(uint8_t th_flags)
{
    char *Flag[7] = {"", "FIN", "SYN", "RST", "PUSH", "ACK", "URG"};
    int first = 1;
    for (int i = 1, j = 1; i < 0x30; i <<= 1, j++)
    {
        if (th_flags & i)
        {
            if (first)
            {
                printf(" [ ");
                first = 0;
            }
            printf("%s ", Flag[j]);
        }
    }
    if (!first)
        printf("]");
}

void PrintTCP(struct trameinfo *t)
{

    struct tcphdr *tcphdr = (struct tcphdr *)t->header_lv3;
    if (t->verbose > 2)
        WriteInBuf(t, "\n");
    WriteInBuf(t, "|Decode TCP: ");
    if (t->verbose > 2)
        WriteInBuf(t, "Checksum= %u, Urgent Pointeur= %u ", tcphdr->check, tcphdr->urg_ptr);
}

int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct tcphdr *tcphdr = (struct tcphdr *)packet;
    trameinfo->header_lv3 = (void *)packet;

    trameinfo->cur+=tcphdr->th_off*4;

    if (trameinfo->verbose > 1)
        PrintTCP(trameinfo);

    SyntheseIP((struct ip *)trameinfo->header_lv2, be16toh(tcphdr->th_sport), be16toh(tcphdr->th_dport), trameinfo->color);

    PrintTCPFlags(tcphdr->th_flags);

    printf(" seq: %u, ack: %u, win: %u ", be32toh(tcphdr->th_seq), be32toh(tcphdr->th_ack), be16toh(tcphdr->th_win));

    if (trameinfo->verbose > 1)
        PrintTCP(trameinfo);

    if (be16toh(tcphdr->th_dport) == 25 || be16toh(tcphdr->th_sport) == 25)
        DecodeSMTP(packet + (tcphdr->th_off * 4), trameinfo);

    return 0;
}
