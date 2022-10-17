
#include "my_arp.h"

void PrintARP(struct arp *arp, struct trameinfo *t)
{
    if (t->verbose == 3)
    {
        WriteInBuf(t, "\n Hardware type = %s Protocol type = ", (arp->hw_type == 1) ? "Ethernet" : "Experimental Ethernet");
        if (arp->pro_type == 0x800)
            WriteInBuf(t, "IP");
        else
            WriteInBuf(t, "Unknown (%i)", arp->pro_type);
    }
    WriteInBuf(t, "Hardware Address Lenght = %i Protocol Addresse Length  =%i", arp->hw_len, arp->pro_len);

    char buf[18];
    INT2MAC(arp->sha, buf);
    WriteInBuf(t, "Sender Phy Addr = %s  Sender Protocol Addr = %s ", buf, inet_ntoa(*arp->sp));
    INT2MAC(arp->tha, buf);
    WriteInBuf(t, "Reciver Phy Addr = %s  Sender Protocol Addr = %s ", buf, inet_ntoa(*arp->tp));
}

int DecodeARP(const u_char *packect, struct trameinfo *trameinfo) // ajouter Synthese ?? oui si avec brocast
{
    (void)trameinfo;
    struct arp *arp = (struct arp *)packect;
    trameinfo->header_lv2 = (void *)packect;

    arp->sp= (struct in_addr *)&arp->spa;
    arp->tp=(struct in_addr *)&arp->tpa;

    char buf[18]={};   

    //Print S-->D ARP like SyntheseIP with great color
    printf("\n\33[%im%s\33[00m:\33[00m", BLUE(trameinfo->color), INT2MAC(arp->sha,buf));
    printf(" --> \33[%im%s\33[00m:\33[00m \33[%imARP \33[00m", BLUE(trameinfo->color), INT2MAC(arp->tha,buf), RED(trameinfo->color));


    if (arp->hw_len != 6)
    {
        printf("No Ethernet lenght");
        return -1;
    }
    if (arp->pro_len != 4)
    {
        printf("No IPv4 length");
        return -1;
    }

    int op = be16toh(arp->op);

    if (op == 0x01)
    {
        printf("Request : %s ask who has ", inet_ntoa(*arp->sp));
        printf("%s", inet_ntoa(*arp->tp));
    }
    else if (op == 0x02)
    {
        char buf2[18];
        INT2MAC(arp->sha, buf2);
        printf("Reply %s is with physic addr %s", inet_ntoa(*arp->sp), buf2);
    }
    else
        printf("Unknown %i", arp->op);

    PrintARP(arp,trameinfo);
    return 0;
}