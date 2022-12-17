#include "my_udp.h"

void beSUDPtoh(struct udp *udp)
{
    udp->D_Port = be16toh(udp->D_Port);
    udp->S_Port = be16toh(udp->S_Port);
    udp->Length = be16toh(udp->Length);
    udp->Sum = be16toh(udp->Sum);
}

void VerboseUDP(struct trameinfo *t)
{

    struct udp *udp = (struct udp *)t->header_lv3;
    WriteInBuf(t, "\n\t\t|UDP: ");
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

    beSUDPtoh(udp); // change packet ideal ou pas ? 
    if (trameinfo->verbose > 1)
        VerboseUDP(trameinfo);

    SyntheseIP(trameinfo, udp->S_Port, udp->D_Port);
    printf("%sUDP %s",RED,RESET);

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
            printf("%sUnreconized Protocol (S %u, D,%u)%s",RED, udp->S_Port, udp->D_Port,RESET);
        }
    }

    return 0;
}
