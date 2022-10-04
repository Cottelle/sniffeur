#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <bits/endian.h>
#include <string.h>

#include "analyseur.h"
#include "protocol.h"


// idée algo au fur et a mesure des decapsulations on met les header dans trameinfo puis a la fin d'un ecaplulation (aka il n'y a plus rien aprés bootp ou si pb) on affiche les infos accumulée ainsi on afficher la version verbose 0 IP S_ip:Port --> D_ip:Port Proto et petite exeplication.



void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("%li ", header->ts.tv_sec);
    struct arg *arg = (struct arg *)args;
    struct trameinfo trameinfo;
    trameinfo.verbose = arg->verbose;
    if (arg->verbose > 3)
    {
        for (int i = 1; i - 1 < (int)header->len; i++)
        {
            printf("%2.2X", packet[i - 1]);
            if (!(i % 16))
                printf("\n");
            else if (!(i % 2))
                printf(" ");
        }
    }
    DecodeEthernet(packet, &trameinfo);
    printf("\n");
    if (arg->verbose > 1)
        printf("\n");
    if (arg->verbose > 2)
        printf("\n");
}

int main(int argc, char **argv)
{
    (void)argc;
    bpf_u_int32 netaddr;
    bpf_u_int32 netmask;
    char errbuf[1024];
    struct arg arg;

    arg.verbose = atoi(argv[2]);

    if (pcap_lookupnet(argv[1], &netaddr, &netmask, errbuf) == -1)
        fprintf(stderr, "Erre pcap_looupnet: %s\n", errbuf);

    pcap_t *p = pcap_open_live(argv[1], 1024, 1, 1000, errbuf);
    if (p == NULL)
        fprintf(stderr, "Erre pcap_open_live: %s\n", errbuf);
    if (pcap_loop(p, -1, callback, (u_char *)&arg) == PCAP_ERROR)
        fprintf(stderr, "Erreur pcap_loop \n"); // perror a set.qma

    pcap_close(p);
}
