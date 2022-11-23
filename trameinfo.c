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


char *TabIpProtocol[] =
    {
        [HOPOPT] = "HOPOPT",
        [ICMP] = "ICMP",
        [IGMP] = "IGMP",
        [GGP] = "GGP",
        [IPinIP] = "IP_in_IP",
        [ST] = "ST",
        [TCP] = "TCP",
        [CBT] = "CBT",
        [EGP] = "EGP",
        [IGP] = "IGP",
        [BBN_RCC_MON] = "BBN_RCC_MON",
        [NVP_II] = "NVP_II",
        [PUP] = "PUP",
        [ARGUS] = "ARGUS",
        [EMCON] = "EMCON",
        [XNET] = "XNET",
        [CHAOS] = "CHAOS",
        [UDP] = "UDP",
        [MUX] = "MUX",
        [DCN_MEAS] = "DCN_MEAS",
        [HMP] = "HMP",
        [PRM] = "PRM",
        [XNS_IDP] = "XNS_IDP",
        [TRUNK_1] = "TRUNK_1",
        [TRUNK_2] = "TRUNK_2",
        [LEAF_1] = "LEAF_1",
        [LEAF_2] = "LEAF_2",
        [RDP] = "RDP",
        [IRTP] = "IRTP",
        [ISO_TP4] = "ISO_TP4",
        [NETBLT] = "NETBLT",
        [MFE_NSP] = "MFE_NSP",
        [MERIT_INP] = "MERIT_INP",
        [DCCP] = "DCCP",
        [THREEPC] = "THREEPC",
        [IDPR] = "IDPR",
        [XTP] = "XTP",
        [DDP] = "DDP",
        [IDPR_CMTP] = "IDPR_CMTP",
        [TPPP] = "TPPP",
        [IL] = "IL",
        [IPv6] = "IPv6",
        [SDRP] = "SDRP",
        [IPv6_Route] = "IPv6_Route",
        [IPv6_Frag] = "IPv6_Frag",
        [IDRP] = "IDRP",
        [RSVP] = "RSVP",
        [GRE] = "GRE",
        [MHRP] = "MHRP",
        [BNA] = "BNA",
        [ESP] = "ESP",
        [AH] = "AH",
        [I_NLSP] = "I_NLSP",
        [SWIPE] = "SWIPE",
        [NARP] = "NARP",
        [MOBILE] = "MOBILE",
        [TLSP] = "TLSP",
        [SKIP] = "SKIP",
        [IPv6_ICMP] = "IPv6_ICMP",
        [IPv6_NoNxt] = "IPv6_NoNxt",
        [IPv6_Opts] = "IPv6_Opts",
        [CFTP] = "CFTP",
        [SAT_EXPAK] = "SAT_EXPAK",
        [KRYPTOLAN] = "KRYPTOLAN",
        [RVD] = "RVD",
        [IPPC] = "IPPC",
        [SAT_MON] = "SAT_MON",
        [VISA] = "VISA",
        [IPCV] = "IPCV",
        [CPNX] = "CPNX",
        [CPHB] = "CPHB",
        [WSN] = "WSN",
        [PVP] = "PVP",
        [BR_SAT_MON] = "BR_SAT_MON",
        [SUN_ND] = "SUN_ND",
        [WB_MON] = "WB_MON",
        [WB_EXPAK] = "WB_EXPAK",
        [ISO_IP] = "ISO_IP",
        [VMTP] = "VMTP",
        [SECURE_VMTP] = "SECURE_VMTP",
        [VINES] = "VINES",
        [TTP] = "TTP",
        [NSFNET_IGP] = "NSFNET_IGP",
        [DGP] = "DGP",
        [TCF] = "TCF",
        [EIGRP] = "EIGRP",
        [OSPFIGP] = "OSPFIGP",
        [Sprite_RPC] = "Sprite_RPC",
        [LARP] = "LARP",
        [MTP] = "MTP",
        [AX25] = "AX.25",
        [IPIP] = "IPIP",
        [MICP] = "MICP",
        [SCC_SP] = "SCC_SP",
        [ETHERIP] = "ETHERIP",
        [ENCAP] = "ENCAP",
        [GMTP] = "GMTP",
        [IFMP] = "IFMP",
        [PNNI] = "PNNI",
        [PIM] = "PIM",
        [ARIS] = "ARIS",
        [SCPS] = "SCPS",
        [QNX] = "QNX",
        [IPComp] = "IPComp",
        [SNP] = "SNP",
        [Compaq_Peer] = "Compaq_Peer",
        [IPX_in_IP] = "IPX_in_IP",
        [VRRP] = "VRRP",
        [PGM] = "PGM",
        [L2TP] = "L2TP",
        [DDX] = "DDX",
        [IATP] = "IATP",
        [STP] = "STP",
        [SRP] = "SRP",
        [UTI] = "UTI",
        [SMP] = "SMP",
        [SM] = "SM",
        [PTP] = "PTP",
        [ISIS_over_IPv4] = "ISIS over IPv4",
        [FIRE] = "FIRE",
        [CRTP] = "CRTP",
        [CRUDP] = "CRUDP",
        [SSCOPMCE] = "SSCOPMCE",
        [IPLT] = "IPLT",
        [SPS] = "SPS",
        [PIPE] = "PIPE",
        [SCTP] = "SCTP",
        [FC] = "FC",
        [RSVP_E2E_IGNORE] = "RSVP_E2E_IGNORE",
        [Mobility_Header] = "Mobility Header",
        [UDPLite] = "UDPLite",
        [MPLS_in_IP] = "MPLS_in_IP",
        [manet] = "manet",
        [HIP] = "HIP",
        [Shim6] = "Shim6",
        [WESP] = "WESP",
        [ROHC] = "ROHC",
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
    char buf[50],*src,*dst;
    if (t->Ipv==AF_INET6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr*)t->header_lv2;
        src = (char *)&(ip6->ip6_src);
        dst = (char *)&(ip6->ip6_dst);
    }
    else if (t->Ipv==AF_INET)
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

    printf("%s%s%s>%s%i%s", BLUE, inet_ntop(t->Ipv,src,buf,50), RESET, YELLOW, SP, RESET);
    printf(" --> %s%s%s>%s%i%s ", BLUE, inet_ntop(t->Ipv,dst,buf,50), RESET, YELLOW, DP, RESET);
    // inet_ntop()
}
