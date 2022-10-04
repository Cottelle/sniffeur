
#include "my_ethernet.h"

void INT2MAC(uint8_t *val, char *buf)
{
    snprintf(buf, 1024, "%x:%x:%x:%x:%x:%x", val[0], val[1], val[2], val[3], val[4], val[5]);
}

void PrintEth(struct ether_header *ether_header, int verbose)
{

    printf("\n|Ethernet Decode:");
    char bufdest[18], bufsourc[1024];
    INT2MAC(ether_header->ether_dhost, bufdest);
    INT2MAC(ether_header->ether_shost, bufsourc);
    if (verbose > 2)
        printf(" MacAddr: Source = %s, Destination = %s, ", bufsourc, bufdest);
    printf(" Data type =");
    uint32_t ethType = ((ether_header->ether_type << 8) + (ether_header->ether_type >> 8)) & (0x0000000FFFF); // INverboseersion ABCD --> CDAB
    switch (ethType)
    {
    case (0x0800):
        printf("IP");
        break;
    case (0x0806):
        printf("ARP");
        break;
    case (0x0835):
        printf("RARP");
        break;
    case (0x86DD):
        printf("IPv6");
        break;
    default:
        printf("Unreconize Data Type %x", ethType); //?
    }
    printf(" ");
}



int DecodeEthernet(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ether_header *ethheader = (struct ether_header *)packet;
    trameinfo->eth_header = (struct ether_header *)packet;

    uint32_t ethType = ((ethheader->ether_type << 8) + (ethheader->ether_type >> 8)) & (0x0000000FFFF); // INversion ABCD --> CDAB
    switch (ethType)
    {
    case (0x0800):
        DecodeIP(packet + sizeof(struct ether_header), trameinfo);
        break;
    case (0x0806):
        printf("ARP\n");
        if (trameinfo->verbose > 1)
            PrintEth(ethheader, trameinfo->verbose);
        break;
    case (0x0835):
        printf("RARP\n");
        if (trameinfo->verbose > 1)
            PrintEth(ethheader, trameinfo->verbose);
        break;
    case (0x86DD):
        printf("IPV6\n");
        if (trameinfo->verbose > 1)
            PrintEth(ethheader, trameinfo->verbose);
        break;
    default:
        printf("Unreconize Dara Type %x\n", ethType);
    }
    return 0;
}
