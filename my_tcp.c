#include "my_tcp.h"

void PrintTCPFlags(uint8_t th_flags)
{
    char *Flag[7] = {"", "FIN", "SYN", "RST", "PUSH", "ACK", "URG"};
    int first = 1;
    for (int i = 1, j = 1; i < 0x30; i <<= 1, j++)
    {
        if (th_flags & i)
        {
            if (first)          //evite de print [] si il n'y a pas de flags
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
    WriteInBuf(t, "\n\t\t|TCP: ");
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

    //Match le port (source ou de destination) avec un protocol connu
    if (be16toh(tcphdr->th_dport) == 25 || be16toh(tcphdr->th_sport) == 25)
        DecodeSMTP(packet + (tcphdr->th_off * 4), trameinfo);

    else if (be16toh(tcphdr->th_dport) == 23 || be16toh(tcphdr->th_sport) == 23)
        DecodeTELNET(packet + (tcphdr->th_off * 4), trameinfo);

    else if (be16toh(tcphdr->th_dport) == 80 || be16toh(tcphdr->th_sport) == 80)
        DecodeHTTP(packet + (tcphdr->th_off * 4), trameinfo);

    else if (be16toh(tcphdr->th_dport) == 110 || be16toh(tcphdr->th_sport) == 110)
        DecodePOP3(packet + (tcphdr->th_off * 4), trameinfo);

    else if (be16toh(tcphdr->th_dport) == 20 || be16toh(tcphdr->th_sport) == 20)
        DecodeFTP(packet + (tcphdr->th_off * 4), trameinfo,0);
    else if (be16toh(tcphdr->th_dport) == 21 || be16toh(tcphdr->th_sport) == 21)
        DecodeFTP(packet + (tcphdr->th_off * 4), trameinfo,1);

    else
        printf("%sUnreconize Protocol (S%i D%i)%s",RED,be16toh(tcphdr->th_sport),be16toh(tcphdr->th_dport),RESET);

    return 0;
}
