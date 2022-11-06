//Fichier genener avec l'aide copilot
#ifndef IPPORTOCOL
#define IPPORTOCOL

#define HOPOPT 0x0
#define ICMP   0x1
#define IGMP   0x2
#define GGP     0x3
#define IPinIP 0x4
#define ST     0x5
#define TCP    0x6
#define CBT    0x7
#define EGP    0x8
#define IGP    0x9
#define BBN_RCC_MON 0xa
#define NVP_II 0xb
#define PUP 0xc
#define ARGUS 0xd
#define EMCON 0xe
#define XNET 0xf
#define CHAOS 0x10
#define UDP 0x11
#define MUX 0x12
#define DCN_MEAS 0x13
#define HMP 0x14
#define PRM 0x15
#define XNS_IDP 0x16
#define TRUNK_1 0x17
#define TRUNK_2 0x18
#define LEAF_1 0x19
#define LEAF_2 0x1a
#define RDP 0x1b
#define IRTP 0x1c
#define ISO_TP4 0x1d
#define NETBLT 0x1e
#define MFE_NSP 0x1f
#define MERIT_INP 0x20
#define DCCP 0x21
#define THREEPC 0x22
#define IDPR 0x23
#define XTP 0x24
#define DDP 0x25
#define IDPR_CMTP 0x26
#define TPPP 0x27
#define IL 0x28
#define IPv6 0x29
#define SDRP 0x2a
#define IPv6_Route 0x2b
#define IPv6_Frag 0x2c
#define IDRP 0x2d
#define RSVP 0x2e
#define GRE 0x2f
#define MHRP 0x30
#define BNA 0x31
#define ESP 0x32
#define AH 0x33
#define I_NLSP 0x34
#define SWIPE 0x35
#define NARP 0x36
#define MOBILE 0x37
#define TLSP 0x38
#define SKIP 0x39
#define IPv6_ICMP 0x3a
#define IPv6_NoNxt 0x3b
#define IPv6_Opts 0x3c
#define CFTP 0x3e
#define SAT_EXPAK 0x40
#define KRYPTOLAN 0x41
#define RVD 0x42
#define IPPC 0x43
#define SAT_MON 0x45
#define VISA 0x46
#define IPCV 0x47
#define CPNX 0x48
#define CPHB 0x49
#define WSN 0x4a
#define PVP 0x4b
#define BR_SAT_MON 0x4c
#define SUN_ND 0x4d
#define WB_MON 0x4e
#define WB_EXPAK 0x4f
#define ISO_IP 0x50
#define VMTP 0x51
#define SECURE_VMTP 0x52
#define VINES 0x53
#define TTP 0x54
#define NSFNET_IGP 0x55
#define DGP 0x56
#define TCF 0x57
#define EIGRP 0x58
#define OSPFIGP 0x59
#define Sprite_RPC 0x5a
#define LARP 0x5b
#define MTP 0x5c
#define AX25 0x5d
#define IPIP 0x5e
#define MICP 0x5f
#define SCC_SP 0x60
#define ETHERIP 0x61
#define ENCAP 0x62
#define GMTP 0x64
#define IFMP 0x65
#define PNNI 0x66
#define PIM 0x67
#define ARIS 0x68
#define SCPS 0x69
#define QNX 0x6a
#define A_N 0x6b
#define IPComp 0x6c
#define SNP 0x6d
#define Compaq_Peer 0x6e
#define IPX_in_IP 0x6f
#define VRRP 0x70
#define PGM 0x71
#define L2TP 0x73
#define DDX 0x74
#define IATP 0x75
#define STP 0x76
#define SRP 0x77
#define UTI 0x78
#define SMP 0x79
#define SM 0x7a
#define PTP 0x7b
#define ISIS_over_IPv4 0x7c
#define FIRE 0x7d
#define CRTP 0x7e
#define CRUDP 0x7f
#define SSCOPMCE 0x80
#define IPLT 0x81
#define SPS 0x82
#define PIPE 0x83
#define SCTP 0x84
#define FC 0x85
#define RSVP_E2E_IGNORE 0x86
#define Mobility_Header 0x87
#define UDPLite 0x88
#define MPLS_in_IP 0x89
#define manet 0x8a
#define HIP 0x8b
#define Shim6 0x8c
#define WESP 0x8d
#define ROHC 0x8e


// Path: ip.h
/*
char *TabIpProtocol[]=
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
};*/


#endif