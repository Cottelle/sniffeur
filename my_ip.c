#include "my_ip.h"




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

void IPOption(void)
{
    printf("There is option ??\n*");
}

void PrintIP(struct trameinfo *t)
{
    struct ip *ip = (struct ip *)t->header_lv2;

    WriteInBuf(t, "\n\t|IP Decode : ");
    WriteInBuf(t, "Total length = %u, ", ip->ip_len);
    if (t->verbose > 2)
    {
        WriteInBuf(t, "IPv%u, Header length = %u*4 Bytes, ", ip->ip_v, ip->ip_hl);
        WriteInBuf(t, "Time to Live = %u,  Checksum = %x, ", ip->ip_ttl, ip->ip_sum);
    }
    if (ip->ip_hl > 5)
        if (t->verbose > 2)
            IPOption();

    WriteInBuf(t,"Protocol = %s(%i)",(ip->ip_p< ROHC +1)? TabIpProtocol[ip->ip_p] :"",ip->ip_p);

    printf(" ");
}

int DecodeIP(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip *ip = (struct ip *)packet;
    trameinfo->header_lv2 = (void *)packet;
    trameinfo->Ipv = AF_INET;

    trameinfo->cur += ip->ip_hl * 4;

    if (trameinfo->verbose > 1)
    {
        PrintIP(trameinfo);
    }

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
        printf("Unreconized Protocol (%x%s)   ", ip->ip_p, (ip->ip_p < ROHC + 1) ? TabIpProtocol[ip->ip_p] : "");
        break;
    }
    return 0;
}
