#include "udp.h"

void beSUDPtoh(struct udp *udp)
{
    udp->D_Port = be16toh(udp->D_Port);
    udp->S_Port = be16toh(udp->S_Port);
    udp->Length = be16toh(udp->Length);
    udp->Sum = be16toh(udp->Sum);
}


void PrintUDP(struct udp *udp, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|Decode UDP: ");
    beSUDPtoh(udp); // Modif packet (ireversible ?)
    if (verbose > 2)
        printf("Length = %u, Checksum = %u, ", udp->Length, udp->Sum);
    printf("Protocol = ");
    switch (be16toh(udp->D_Port))
    {
    case 67:
    case 68:
        printf("Bootp\n\n");
        break;

    default:
        printf("Unreconized Protocol (%u)", udp->D_Port); //?
        break;
    }
}


int DecodeUDP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct udp *udp = (struct udp *)packet;
    trameinfo->header_lv3 = (void *)packet;

    Synthese((struct ip *)trameinfo->header_lv2, be16toh(udp->S_Port), be16toh(udp->D_Port));

    switch (be16toh(udp->D_Port))
    {
    case 67:
    case 68:
        DecodeBootp(packet + 8, trameinfo);
        break;

    default:
        printf("Unreconized Protocol (%u)", udp->S_Port);
        if (trameinfo->verbose > 1)
        {
            PrintEth(trameinfo->eth_header, trameinfo->verbose);
            PrintIP((struct ip *)trameinfo->header_lv2, trameinfo->verbose);
            PrintUDP(udp, trameinfo->verbose);
        }
        break;
    }

    return 0;
}

