#include "trameinfo.h"

char *GREEN = "\33[32m";
char *BLUE = "\33[34m";
char *RED = "\33[31m";
char *YELLOW = "\33[33m";
char *MAGENTA = "\33[35m";
char *CYAN = "\33[36m";
char *WHITE = "\33[37m";
char *BLACK = "\33[30m";
char *RESET = "\33[00m";

char TabIpProtocol[143][20] = {             //All ip protocol (with correct number)
    "HOPOPT",
    "ICMP",
    "IGMP",
    "GGP",
    "IPv4",
    "ST",
    "TCP",
    "CBT",
    "EGP",
    "IGP",
    "BBN-RCC-MON",
    "NVP-II",
    "PUP",
    "ARGUS",
    "EMCON",
    "XNET",
    "CHAOS",
    "UDP",
    "MUX",
    "DCN-MEAS",
    "HMP",
    "PRM",
    "XNS-IDP",
    "TRUNK-1",
    "TRUNK-2",
    "LEAF-1",
    "LEAF-2",
    "RDP",
    "IRTP",
    "ISO-TP4",
    "NETBLT",
    "MFE-NSP",
    "MERIT-INP",
    "DCCP",
    "3PC",
    "IDPR",
    "XTP",
    "DDP",
    "IDPR-CMTP",
    "TP++",
    "IL",
    "IPv6",
    "SDRP",
    "IPv6-Route",
    "IPv6-Frag",
    "IDRP",
    "RSVP",
    "GRE",
    "DSR",
    "BNA",
    "ESP",
    "AH",
    "I-NLSP",
    "SWIPE",
    "NARP",
    "MOBILE",
    "TLSP",
    "SKIP",
    "IPv6-ICMP",
    "IPv6-NoNxt",
    "IPv6-Opts",
    "CFTP",
    "SAT-EXPAK",
    "KRYPTOLAN",
    "RVD",
    "IPPC",
    "SAT-MON",
    "VISA",
    "IPCV",
    "CPNX",
    "CPHB",
    "WSN",
    "PVP",
    "BR-SAT-MON",
    "SUN-ND",
    "WB-MON",
    "WB-EXPAK",
    "ISO-IP",
    "VMTP",
    "SECURE-VMTP",
    "VINES",
    "TTP",
    "IPTM",
    "NSFNET-IGP",
    "DGP",
    "TCF",
    "EIGRP",
    "OSPFIGP",
    "Sprite-RPC",
    "LARP",
    "MTP",
    "AX.25",
    "IPIP",
    "MICP",
    "SCC-SP",
    "ETHERIP",
    "ENCAP",
    "GMTP",
    "IFMP",
    "PNNI",
    "PIM",
    "ARIS",
    "SCPS",
    "QNX",
    "A/N",
    "IPComp",
    "SNP",
    "Compaq-Peer",
    "IPX-in-IP",
    "VRRP",
    "PGM",
    "0-hop",
    "L2TP",
    "DDX",
    "IATP",
    "STP",
    "SRP",
    "UTI",
    "SMP",
    "SM",
    "PTP",
    "ISIS over IPv4",
    "FIRE",
    "CRTP",
    "CRUDP",
    "SSCOPMCE",
    "IPLT",
    "SPS",
    "PIPE",
    "SCTP",
    "FC",
    "RSVP-E2E-IGNORE",
    "Mobility Header",
    "UDPLite",
    "MPLS-in-IP",
    "manet",
    "HIP",
    "Shim6",
    "WESP",
    "ROHC",
    "Ethernet",
};


char *INT2MAC(uint8_t *val, char *buf)
{
    snprintf(buf, 1024, "%x:%x:%x:%x:%x:%x", val[0], val[1], val[2], val[3], val[4], val[5]);
    return buf; // for easy print
}

void WriteInBuf(struct trameinfo *t, char *format, ...)
{
    int i;
    va_list ap;
    va_start(ap, format);

    while ((i = vsnprintf(t->bufverbose, 0, format, ap)) + t->write_buf >= t->size_buf) // test si il y a de la place. Crer de la place sinon
    {
        t->size_buf *= 2;
        t->bufverbose = realloc(t->bufverbose, t->size_buf);
        if (!t->bufverbose)
        {
            fprintf(stderr, "realloc failed");
            exit(1);
        }
    }
    va_end(ap);
    va_start(ap, format);
    if (i == -1 || (i = vsnprintf(t->bufverbose + t->write_buf, t->size_buf - t->write_buf, format, ap)) == -1)
    {
        fprintf(stderr, "vsnprintf error");
        exit(2);
    }
    t->write_buf += i;
}

void SyntheseIP(struct trameinfo *t, int SP, int DP)
{
    char buf[50], *src, *dst;
    if (t->Ipv == AF_INET6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)t->header_lv2;
        src = (char *)&(ip6->ip6_src);
        dst = (char *)&(ip6->ip6_dst);
    }
    else if (t->Ipv == AF_INET)
    {
        struct ip *ip = t->header_lv2;
        src = (char *)&(ip->ip_src);
        dst = (char *)&(ip->ip_dst);
    }
    else
    {
        printf("Error Ipv not set\n continue\n");
        return;
    }

    printf("%s%s%s>%s%i%s", BLUE, inet_ntop(t->Ipv, src, buf, 50), RESET, YELLOW, SP, RESET);
    printf(" --> %s%s%s>%s%i%s ", BLUE, inet_ntop(t->Ipv, dst, buf, 50), RESET, YELLOW, DP, RESET);
    // inet_ntop()
}

void SyntheseIPU(struct trameinfo *t)
{
    char buf[50], *src, *dst;
    if (t->Ipv == AF_INET6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)t->header_lv2;
        src = (char *)&(ip6->ip6_src);
        dst = (char *)&(ip6->ip6_dst);
    }
    else if (t->Ipv == AF_INET)
    {
        struct ip *ip = t->header_lv2;
        src = (char *)&(ip->ip_src);
        dst = (char *)&(ip->ip_dst);
    }
    else
    {
        printf("Error Ipv not set\n continue\n");
        return;
    }

    printf("%s%s%s", BLUE, inet_ntop(t->Ipv, src, buf, 50), RESET);
    printf(" --> %s%s%s ", BLUE, inet_ntop(t->Ipv, dst, buf, 50), RESET);
    // inet_ntop()
}
