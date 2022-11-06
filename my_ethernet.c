#include "my_ethernet.h"


void VerboseEth(struct trameinfo *t)
{

    struct ether_header *ether_header = t->eth_header;
    WriteInBuf(t, "\n|Ethernet Decode:");
    char bufdest[18], bufsourc[1024];
    INT2MAC(ether_header->ether_dhost, bufdest);
    INT2MAC(ether_header->ether_shost, bufsourc);
    if (t->verbose > 2)
        WriteInBuf(t,"Source = %s, Destination = %s, ", bufsourc, bufdest);
    WriteInBuf(t," Data type =");
    uint32_t ethType = ((ether_header->ether_type << 8) + (ether_header->ether_type >> 8)) & (0x0000000FFFF); // INverboseersion ABCD --> CDAB
    switch (ethType)
    {
    case (0x0800):
        WriteInBuf(t,"IP");
        break;
    case (0x0806):
        WriteInBuf(t,"ARP");
        break;
    case (0x0835):
        WriteInBuf(t,"RARP");
        break;
    case (0x86DD):
        WriteInBuf(t,"IPv6");
        break;
    default:
        WriteInBuf(t,"Unreconize Data Type %x", ethType); //?
    }
    WriteInBuf(t," ");
}

int DecodeEthernet(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ether_header *ethheader = (struct ether_header *)packet;
    trameinfo->eth_header = (struct ether_header *)packet;

    trameinfo->cur+=sizeof(struct ether_header);

    if (trameinfo->verbose>1)
        VerboseEth(trameinfo);

    uint32_t ethType = ((ethheader->ether_type << 8) + (ethheader->ether_type >> 8)) & (0x0000000FFFF); // INversion ABCD --> CDAB
    switch (ethType)
    {
    case (0x0800):
        DecodeIP(packet + sizeof(*ethheader), trameinfo);
        break;
    case (0x0806):
        // DecodeARP(packet + sizeof(*ethheader), trameinfo);
        printf("ARP In process");
        break;
    case (0x0835):
        printf("RARP");
        break;
    case (0x86DD):
        // printf("IPV6");
        DecodeIP6(packet+sizeof(*ethheader),trameinfo);
        break;
    default:
        printf("Unreconize Dara Type %x\n", ethType);
    }

    
    return 0;
}
