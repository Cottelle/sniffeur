
#include "analyseur.h"

// idée algo au fur et a mesure des decapsulations on met les header dans trameinfo puis a la fin d'un ecaplulation (aka il n'y a plus rien aprés bootp ou si pb) on affiche les infos accumulée ainsi on afficher la version verbose 0 IP S_ip:Port --> D_ip:Port Proto et petite exeplication.

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct arg *arg = (struct arg *)args;

    printf("\33[%im-%li-\33[00m ", GREEN(arg->color), header->ts.tv_sec - arg->starttime);

    struct trameinfo trameinfo;
    trameinfo.verbose = arg->verbose;
    trameinfo.color = arg->color;

    trameinfo.size_buf = BUFVERBOSE_INITSIZE;
    trameinfo.write_buf = 0;
    if (trameinfo.verbose > 1)
    {
        trameinfo.bufverbose = malloc(BUFVERBOSE_INITSIZE);
        if (!trameinfo.bufverbose)
        {
            printf("malloc error");
            exit(1);
        }
    }

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
    if (trameinfo.verbose > 1)
    {
        printf("%s", trameinfo.bufverbose);
        free(trameinfo.bufverbose);
    }
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
    struct timeval starttime;
    struct arg arg;
    struct options_t options;

    parseArgs(argc, argv, &options);

    arg.verbose = options.verbose;
    arg.color = options.colors;

    pcap_t *p;

    if (options.interface)
    {
        if (pcap_lookupnet(options.interface, &netaddr, &netmask, errbuf) == -1)
        {
            fprintf(stderr, "Erre pcap_looupnet: %s\n", errbuf);
            exit(1);
        }
        p = pcap_open_live(options.interface, 1024, 1, 1000, errbuf);
        if (p == NULL)
        {
            fprintf(stderr, "Erre pcap_open_live: %s\n", errbuf);
            exit(1);
        }
    }
    else if (options.off_file) // if offline and interface are in argument the interface are chose
    {
        p = pcap_open_offline(options.off_file, errbuf);
        if (!p)
        {
            fprintf(stderr, "Erre pcap_open_offline: %s\n", errbuf);
            exit(1);
        }
    }

    else
    {
        fprintf(stderr, "Not interface chosen please chose with -i <interface> option or -o <file_name> for offline\n");
        exit(2);
    }

    if (gettimeofday(&starttime, NULL) == -1)
        perror("gettimeofday");
    arg.starttime = starttime.tv_sec;
    if (pcap_loop(p, options.count, callback, (u_char *)&arg) == PCAP_ERROR)
        fprintf(stderr, "Erreur pcap_loop \n"); // perror a set.qma

    pcap_close(p);
}
