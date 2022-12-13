#include "my_bootp.h"

void PrintBootp(struct trameinfo *t)
{
    struct bootp *bootp = (struct bootp *)t->header_lv4;

    if (t->verbose > 2)
        WriteInBuf(t, "\n");
    WriteInBuf(t, "|Bootp: MyIP= %s, ", inet_ntoa(bootp->ciaddr));
    WriteInBuf(t, "YourIP= %s, ", inet_ntoa(bootp->yiaddr));
    WriteInBuf(t, "ServIP= %s, ", inet_ntoa(bootp->siaddr));
    WriteInBuf(t, "GetwayIP= %s, ", inet_ntoa(bootp->giaddr));
}

int DecodeBootp(const u_char *packet, struct trameinfo *trameinfo)
{
    struct bootp *bootp = (struct bootp *)packet;

    trameinfo->cur+=HEADER_LEN + SNAME_LEN + FILE_LEN;

    if (trameinfo->verbose > 1)
        PrintBootp(trameinfo);


    bootp->vend = (const uint16_t *)(packet + HEADER_LEN + SNAME_LEN + FILE_LEN);
    trameinfo->header_lv4 = (void *)bootp;

    if (be16toh(bootp->vend[0]) == 0x6382 && be16toh(bootp->vend[1]) == 0x5363)
    {
        trameinfo->cur+=2;
        DecodeDHCP((const u_char *)(bootp->vend + 2), trameinfo);
    }
    else
    {
        printf("Bootp ");
        if (bootp->op == 1)
            printf("Request");
        else if (bootp->op == 2)
            printf("Response");
        else
            printf("Unknow operation (%u)\n*", bootp->op);
    }
    return 0;
}
