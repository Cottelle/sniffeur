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

    struct udp *udp = (struct udp *)t->header_lv3;
    WriteInBuf(t, "\n\t\t|Decode UDP: ");
    if (t->verbose > 2)
        WriteInBuf(t, "Length = %u, Checksum = %u, ", udp->Length, udp->Sum);
    WriteInBuf(t, "Protocol = ");
    switch ((udp->D_Port))
    {
    case 67:
    case 68:
        WriteInBuf(t, "Bootp ");
        break;

    case 53:
        WriteInBuf(t, "DNS ");
        break;

    default:
        switch ((udp->S_Port))
        {
        case 67:
        case 68:
            WriteInBuf(t, "Bootp ");
            break;

        case 53:
            WriteInBuf(t, "DNS ");
            break;

        default:
            WriteInBuf(t, "Unreconized Protocol (%u %u)", udp->S_Port, udp->D_Port);
        }
    }
}

int DecodeUDP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct udp *udp = (struct udp *)packet;
    trameinfo->header_lv3 = (void *)packet;

    trameinfo->cur += 8;

    beSUDPtoh(udp); // change the bit range
    if (trameinfo->verbose > 1)
        PrintUDP(trameinfo);

    SyntheseIP((struct ip *)trameinfo->header_lv2, (udp->S_Port), (udp->D_Port));

    switch (udp->D_Port)
    {
    case 67:
    case 68:
        DecodeBootp(packet + 8, trameinfo);
        break;
    case 53:
        DecodeDNS(packet + 8, trameinfo);
        break;
    default:

        switch (udp->S_Port)
        {
        case 67:
        case 68:
            DecodeBootp(packet + 8, trameinfo);
            break;
        case 53:
            DecodeDNS(packet + 8, trameinfo);
            break;
        default:
            printf("Unreconized Protocol (S %u, D,%u)", udp->S_Port, udp->D_Port);
        }
    }

    return 0;
}
