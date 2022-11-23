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

void VerboseTCP(struct trameinfo *t)
{

    struct tcphdr *tcphdr = (struct tcphdr *)t->header_lv3;
    WriteInBuf(t, "\n\t\t|Decode TCP: ");
    if (t->verbose > 2)
        WriteInBuf(t, "Checksum= %u, Urgent Pointeur= %u ", tcphdr->check, tcphdr->urg_ptr);
    WriteInBuf(t,"Data offset= %u",tcphdr->th_off);
}

int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct tcphdr *tcphdr = (struct tcphdr *)packet;
    trameinfo->header_lv3 = (void *)packet;

    trameinfo->cur += tcphdr->th_off * 4;

    if (trameinfo->verbose > 1)
        VerboseTCP(trameinfo);

    SyntheseIP(trameinfo, be16toh(tcphdr->th_sport), be16toh(tcphdr->th_dport));
    printf("%sTCP%s",RED,RESET);

    PrintTCPFlags(tcphdr->th_flags);

    printf(" seq: %u, ack: %u, win: %u ", be32toh(tcphdr->th_seq), be32toh(tcphdr->th_ack), be16toh(tcphdr->th_win));

    if (be16toh(tcphdr->th_dport) == 25 || be16toh(tcphdr->th_sport) == 25)
        DecodeSMTP(packet + (tcphdr->th_off * 4), trameinfo);

    else
        printf("%sUnreconize Protocol (%i %i)%s",RED,be16toh(tcphdr->th_dport),be16toh(tcphdr->th_sport),RESET);

    return 0;
}
