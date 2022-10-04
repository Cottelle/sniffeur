#include "protocol.h"

void Synthese(struct ip *ip, int SP, int DP)
{
    // if (color)
    //     printf("\033[34;01m");
    printf("%s:%i", inet_ntoa(ip->ip_src), SP);
    printf("-->%s:%i %s", inet_ntoa(ip->ip_dst), DP, (ip->ip_p == 0x11) ? "UDP " : ((ip->ip_p == 0x06) ? "TCP" : "??"));
    // if (color)
    //     printf("\033[00m");
}

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


void DHCPnames_reso(int code, char *buf)
{
    switch (code)
    {
    case 1:
        strcpy(buf, "mask");
        break;
    case 2:
        strcpy(buf, "time offset");
        break;
    case 3:
        strcpy(buf, "router");
        break;
    case 6:
        strcpy(buf, "DNS");
        break;
    case 12:
        strcpy(buf, "host name");
        break;
    case 15:
        strcpy(buf, "domain name");
        break;
    case 28:
        strcpy(buf, "brocast addr");
        break;
    case 44:
        strcpy(buf, "netbios server");
        break;
    case 47:
        strcpy(buf, "netbios scope");
        break;
    case 51:
        strcpy(buf, "lease time");
        break;
    case 54:
        strcpy(buf, "server id");
        break;
    case 61:
        strcpy(buf, "client id");
        break;
    default:
        // snprintf(buf,16, "Unreconized %i",code);
        snprintf(buf, 16, "U%i", code);
        break;
    }
    return;
}

void PrintDHCP(struct dhcps dhcps[64], int verbose)
{
    char name[16];
    if (verbose > 2)
    {
        printf("\n|Decode DHCP: ");
        for (int i = 0; i < 64; i++)
            if (dhcps[i].present)
            {
                DHCPnames_reso(i, name);
                printf("%s= ", name);
                if (i == 1 || i == 3 || i == 28 || i == 54 || i == 61)
                    printf("%s ", inet_ntoa(*(struct in_addr *)(dhcps[i].str)));
                else if (i == 12 || i == 15)
                    printf("%s ", dhcps[i].str);
                else if (i == 2 || i == 44 || i == 47 || i == 51) // a peut être verifier
                {
                    unsigned long long sum = 0;
                    for (int j = 0; j < dhcps[i].size; j++)
                        sum += dhcps[i].str[j] << (dhcps[i].size - j - 1) * 8;
                    printf("%lli ", sum);
                }
                else if(i==6) // DNS
                {
                    if (dhcps[i].size % 4 == 0)
                    {
                        printf("IP no 4");
                        continue;
                    }
                    int nub = dhcps[i].size / 4;
                    for (int j = 0; j < nub; j++)
                        printf("%s", inet_ntoa(*(struct in_addr *)(dhcps[i].str + j * 4)));
                }
            }
    }
    else // verbose ==2
    {
        for (int i = 0; i < 64; i++)
            if (dhcps[i].present)
            {
                DHCPnames_reso(i, name);
                printf("%s= ", name);
                if (i == 1 || i == 54 || i == 61)
                    printf(" %s ", inet_ntoa(*(struct in_addr *)(dhcps[i].str)));
                else if (i == 15)
                    printf(" %s ", dhcps[i].str);
            }
    }
}

void DecodeDHCP(const u_char *vend, struct trameinfo *trameinfo)
{
    printf("DHCP ");
    int i = 0;
    struct dhcps dhcps[64];
    memset(dhcps, 0, 64 * sizeof(struct dhcps));
    while (vend[i] != 0xff)
    {
        dhcps[vend[i]].str = vend + i + 2; // evite de faire une structure, alege le code au detriment de la mémoire.
        dhcps[vend[i]].size = vend[i + 1];
        dhcps[vend[i]].present = 1;
        i += vend[i + 1] + 2;
    }
    if (dhcps[53].present) //
        switch (dhcps[53].str[0])
        {
        case 1:
            printf("discover ");
            break;
        case 2:
            printf("offer ");
            break;

        case 3:
            printf("request ");
            if (dhcps[50].present)
                printf(": %s", inet_ntoa(*(struct in_addr *)(dhcps[50].str)));
            break;

        case 5:
            printf("ack ");
            break;

        case 7:
            printf("release ");
            break;

        default:
            printf("Unreconized %i op ", dhcps[53].str[0]);
            break;
        }
    if (dhcps[55].present)
    {
        printf(" req list =[");
        char name[16];
        for (char i = 0; i < dhcps[55].size; i++)
        {
            DHCPnames_reso(dhcps[55].str[(int)i], name);
            printf("%s,", name);
        }
        printf("]");
    }
    if (trameinfo->verbose > 1)
    {
        PrintEth(trameinfo->eth_header, trameinfo->verbose);
        PrintIP((struct ip *)trameinfo->header_lv2, trameinfo->verbose);
        PrintUDP((struct udp *)trameinfo->header_lv3, trameinfo->verbose);
        PrintBootp((struct bootp *)trameinfo->header_lv4, trameinfo->verbose);
        PrintDHCP(dhcps, trameinfo->verbose);
    }
}


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
        printf("Source = %s, Destination = %s, ", bufsourc, bufdest);
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


void IPOption(void)
{
    printf("There is option ??\n*");
}


void PrintIP(struct ip *ip, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|IP Decode : ");
    printf("Total length = %u, ", ip->ip_len);
    if (verbose > 2)
    {
        printf("IPv%u, Header length = %u*4 Bytes, ", ip->ip_v, ip->ip_hl);
        printf("Time to Live = %u,  Checksum = %x, ", ip->ip_ttl, ip->ip_sum);
    }
    if (ip->ip_hl > 5)
        if (verbose > 2)
            IPOption();

    if (verbose > 2)
        printf("There is no Option, ");
    switch (ip->ip_p)
    {
    case 0x06:
        printf("TCP Protocol");
        break;
    case 0x11:
        printf("UDP Protocol");
        break;
    default:
        break;
    }
    printf(" ");
}


int DecodeIP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip *ip = (struct ip *)packet;
    trameinfo->header_lv2 = (void *)packet;

    if (ip->ip_hl > 5)
        IPOption();

    switch (ip->ip_p)
    {
    case 0x06:
        DecodeTCP(packet + 4 * ip->ip_hl, trameinfo);
        break;
    case 0x11:
        DecodeUDP(packet + 4 * ip->ip_hl, trameinfo);
        break;
    default:
        printf("Unreconized Protocol (%x)   ", ip->ip_p);
        if (trameinfo->verbose > 1)
        {
            PrintEth(trameinfo->eth_header, trameinfo->verbose);
            PrintIP(ip, trameinfo->verbose);
        }
        break;
    }
    return 0;
}


void PrintTCP(struct tcphdr *tcphdr, int verbose)
{
    if (verbose > 2)
        printf("\n");
    printf("|Decode TCP: ");
    if (verbose > 2)
        printf("Checksum= %u, Urgent Pointeur= %u ", tcphdr->check, tcphdr->urg_ptr);
}




int DecodeTCP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct tcphdr *tcphdr = (struct tcphdr *)packet;
    trameinfo->header_lv3 = (void *)packet;

    Synthese((struct ip *)trameinfo->header_lv2, tcphdr->th_sport, tcphdr->th_dport);

    printf(" seq= %u ack= %u win= %u ", be16toh(tcphdr->th_seq), be16toh(tcphdr->th_ack), tcphdr->th_win);

    if (trameinfo->verbose > 1)
    {
        PrintEth(trameinfo->eth_header, trameinfo->verbose);
        PrintIP((struct ip *)trameinfo->header_lv2, trameinfo->verbose);
        PrintTCP(tcphdr, trameinfo->verbose);
    }

    return 0;
}


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

