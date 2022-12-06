#ifndef MYIPV6
#define MYIPV6

#include <netinet/ip6.h>

#include "trameinfo.h"
#include "my_tcp.h"
#include "my_udp.h"
#include "ip_protocol.h"


/*char IPPROTOCOL[143][20] = {
    "HOPOPT","ICMP","IGMP",
    "GGP","IPv4","ST",
    "TCP","CBT","EGP",
    "IGP","BBN-RCC-MON","NVP-II",
    "PUP","ARGUS","EMCON",
    "XNET","CHAOS","UDP",
    "MUX","DCN-MEAS","HMP",
    "PRM","XNS-IDP","TRUNK-1",
    "TRUNK-2","LEAF-1","LEAF-2",
    "RDP","IRTP","ISO-TP4",
    "NETBLT","MFE-NSP","MERIT-INP",
    "DCCP","3PC","IDPR",
    "XTP","DDP","IDPR-CMTP",
    "TP++","IL","IPv6",
    "SDRP","IPv6-Route","IPv6-Frag",
    "IDRP","RSVP","GRE",
    "DSR","BNA","ESP",
    "AH","I-NLSP","SWIPE",
    "NARP","MOBILE","TLSP",
    "SKIP","IPv6-ICMP","IPv6-NoNxt",
    "IPv6-Opts","CFTP","SAT-EXPAK",
    "KRYPTOLAN","RVD","IPPC",
    "SAT-MON","VISA","IPCV",
    "CPNX","CPHB","WSN",
    "PVP","BR-SAT-MON","SUN-ND",
    "WB-MON","WB-EXPAK","ISO-IP",
    "VMTP","SECURE-VMTP","VINES",
    "TTP","IPTM","NSFNET-IGP",
    "DGP","TCF","EIGRP",
    "OSPFIGP","Sprite-RPC","LARP","MTP",
    "AX.25","IPIP","MICP",
    "SCC-SP","ETHERIP","ENCAP",
    "GMTP","IFMP","PNNI",
    "PIM","ARIS","SCPS",
    "QNX","A/N","IPComp",
    "SNP","Compaq-Peer",
    "IPX-in-IP","VRRP",
    "PGM","0-hop","L2TP",
    "DDX","IATP","STP",
    "SRP","UTI","SMP",
    "SM","PTP","ISIS over IPv4",
    "FIRE","CRTP","CRUDP",
    "SSCOPMCE","IPLT","SPS",
    "PIPE","SCTP","FC",
    "RSVP-E2E-IGNORE","Mobility Header","UDPLite",
    "MPLS-in-IP","manet","HIP",
    "Shim6","WESP","ROHC",
    "Ethernet",
};*/


/**
 * @brief Decode the IP6's info since packet
 */
int DecodeIP6(const u_char *packet, struct trameinfo *trameinfo);

#endif