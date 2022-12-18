
#include "analyseur.h"

void error(pcap_t *p, char *prefix)
{
    pcap_perror(p, prefix);
    exit(1);
}


void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct arg *arg = (struct arg *)args;

    if (arg->starttime < 0)                 // Si le l'input est un fichier alors on set le temps au premier paquet 
        arg->starttime = header->ts.tv_sec;

    if (arg->verbose > 3)                   //Print le paquet (notamment pour debuger)
    {
        for (int i = 1; i - 1 < (int)header->len; i++)
        {
            printf("%2.2X", packet[i - 1]);
            if (!(i % 16))
                printf("\n");
            else if (!(i % 2))
                printf(" ");
        }
        printf("\n");
    }

    printf("%s-%li-%s ", GREEN, header->ts.tv_sec - arg->starttime, RESET);     

    struct trameinfo trameinfo;

    trameinfo.len = header->len;
    trameinfo.packet = packet;
    trameinfo.cur = 0;

    trameinfo.verbose = arg->verbose;

    if (trameinfo.verbose > 1)
    {
        trameinfo.bufverbose = malloc(BUFVERBOSE_INITSIZE);
        if (!trameinfo.bufverbose)
        {
            printf("malloc error");
            exit(1);
        }
    }
    trameinfo.size_buf = BUFVERBOSE_INITSIZE;
    trameinfo.write_buf = 0;

    DecodeEthernet(packet, &trameinfo);         //On commence par decoder la trame ethernet (les autres decode se feront dans ethernet puis ip ...)
    if (trameinfo.verbose > 1)                  // Si il y a de la verbose print les info contenu dans le buffeur
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

    parseArgs(argc, argv, &options);    //Parse les arguments

    arg.verbose = options.verbose;

    if (!options.colors)                // Annulles les couleurs
    {
        GREEN = "";
        BLUE = "";
        RED = "";
        YELLOW = "";
        MAGENTA = "";
        CYAN = "";
        WHITE = "";
        BLACK = "";
        RESET = "";
    }

    pcap_t *p;

    if (options.interface)
    {
        if (pcap_lookupnet(options.interface, &netaddr, &netmask, errbuf) == -1)
        {
            fprintf(stderr, "Error pcap_looupnet: %s\n", errbuf);
            exit(1);
        }
        p = pcap_open_live(options.interface, 1024, 1, 1000, errbuf);
        if (p == NULL)
        {
            fprintf(stderr, "Error pcap_open_live: %s\n", errbuf);
            exit(1);
        }
    }
    else if (options.off_file) // if offline and interface are in argument the interface are chose
    {
        p = pcap_open_offline(options.off_file, errbuf);
        if (!p)
        {
            fprintf(stderr, "Error pcap_open_offline: %s\n", errbuf);
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "Not interface chosen please chose with -i <interface> option or -o <file_name> for offline\n");
        exit(2);
    }

    if(options.filter)
    {
        struct bpf_program fp;
        if (pcap_compile(p,&fp,options.filter,0,0)==-1)
        {
            fprintf(stderr,"Error pcap_compile\n");
            exit(1);
        }
        if (pcap_setfilter(p,&fp)==-1)
        {
            fprintf(stderr,"Error pcap_setfilter\n");
            exit(1);
        }
    }

    if (options.interface)
    {

        if (gettimeofday(&starttime, NULL) == -1)
            perror("gettimeofday");
        arg.starttime = starttime.tv_sec;
    }
    else
        arg.starttime = -1;

    if (pcap_loop(p, options.count, callback, (u_char *)&arg) == PCAP_ERROR)
        error(p, "pcap_loop error :");

    pcap_close(p);
}
