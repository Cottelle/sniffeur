#include "my_ipv6.h"

static char *TabIpProtocol[] =
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

void VerboseIP6(struct trameinfo *t)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)t->header_lv2;
    WriteInBuf(t, "\n\t|Decode IPv6 :");
    if (t->verbose > 2)
        WriteInBuf(t, "Verion= %i, Trafic= %i, Flow= %i", (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & 0xf0) >> 4, (ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xff0f, be16toh(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow >> 16));
    WriteInBuf(t, "Lenght= %i, Next= %s(%i)", ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt < ROHC + 1) ? TabIpProtocol[ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt] : "", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    if (t->verbose>2)
        WriteInBuf(t,", Hop limit= %i",ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
}

int DecodeIP6(const u_char *packet, struct trameinfo *trameinfo)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
    trameinfo->header_lv2 = (void *)ip6;
    trameinfo->Ipv = AF_INET6;

    trameinfo->cur += sizeof(*ip6);

    if (trameinfo->verbose > 1)
        VerboseIP6(trameinfo);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
    case 0X6:
        DecodeTCP(packet + sizeof(*ip6), trameinfo);
        break;

    case 0x11:
        DecodeUDP(packet + sizeof(*ip6), trameinfo);
        break;
    default:
        printf("Unreconized Protocol %i", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        break;
    }

    return 0;
}