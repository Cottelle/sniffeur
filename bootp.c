

#include "bootp.h"

void PrintBootp(struct bootp *bootp, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|Decode Bootp: MyIP= %s, ", inet_ntoa(bootp->ciaddr));
    printf("YourIP= %s, ", inet_ntoa(bootp->yiaddr));
    printf("ServIP= %s, ", inet_ntoa(bootp->siaddr));
    printf("GetwayIP= %s, ", inet_ntoa(bootp->giaddr));
}


int DecodeBootp(const u_char *packet, struct trameinfo *trameinfo)
{
    (void)trameinfo;
    struct bootp *bootp = (struct bootp *)packet;
    bootp->vend = (const uint16_t *)(packet + HEADER_LEN + SNAME_LEN + FILE_LEN);
    trameinfo->header_lv4 = (void *)bootp;

    if (be16toh(bootp->vend[0]) == 0x6382 && be16toh(bootp->vend[1]) == 0x5363)
    {
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
        if (trameinfo->verbose > 1)
            PrintBootp(bootp, trameinfo->verbose);
    }
    return 0;
}