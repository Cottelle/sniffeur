#include "my_udp.h"

void beSUDPtoh(struct udp *udp)
{
    udp->D_Port = be16toh(udp->D_Port);
    udp->S_Port = be16toh(udp->S_Port);
    udp->Length = be16toh(udp->Length);
    udp->Sum = be16toh(udp->Sum);
}

void PrintUDP(struct trameinfo *t)
{
    if (t->verbose > 2)
        WriteInBuf(t, "\n");

    struct udp *udp = (struct udp *)t->header_lv3;
    WriteInBuf(t, "|Decode UDP: ");
    beSUDPtoh(udp); // Modif packet (ireversible ?)
    if (t->verbose > 2)
        WriteInBuf(t, "Length = %u, Checksum = %u, ", udp->Length, udp->Sum);
    WriteInBuf(t, "Protocol = ");
    switch (be16toh(udp->D_Port))
    {
    case 67:
    case 68:
        WriteInBuf(t, "Bootp\n\n");
        break;

    default:
        WriteInBuf(t, "Unreconized Protocol (%u)", udp->D_Port); //?
        break;
    }
}

int DecodeUDP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct udp *udp = (struct udp *)packet;
    trameinfo->header_lv3 = (void *)packet;

    if (trameinfo->verbose > 1)
            PrintUDP(trameinfo);

    SyntheseIP((struct ip *)trameinfo->header_lv2, be16toh(udp->S_Port), be16toh(udp->D_Port), trameinfo->color);

    switch (be16toh(udp->D_Port))
    {
    case 67:
    case 68:
        DecodeBootp(packet + 8, trameinfo);
        break;

    default:
        printf("Unreconized Protocol (%u)", udp->S_Port);
        
        break;
    }

    return 0;
}
