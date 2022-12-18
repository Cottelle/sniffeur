#include "my_dns.h"

char *(type)[] = {
    [1] "A",
    [28] "AAAA",        
    [18] "AFSDB",   //pas implémenté
    [12] "PTR",     //pas implémenté
    [6] "SOA",      //pas implémenté
    [5] "CNAME",        
};

char *PrintDNSName(char *name, struct trameinfo *t, dns_header_t *head)     //Print dns name (google.com.), recursif
{
    int size = *name;
    while ((size = *name) != 0)
    {
        if ((((unsigned char *)name)[0]) == 0xc0)
        {
            char *recname = (char *)(head) + ((unsigned char *)name)[1];
            PrintDNSName(recname, t, head);
            name += 2;
            return name;
        }
        name++;
        for (int i = 0; i < size; i++, name++)
        {
            if (!t)
                printf("%c", *name);
            else
                WriteInBuf(t, "%c", *name);
        }
        if (!t)
            printf(".");
        else
            WriteInBuf(t, ".");
    }
    return name + 1;
}

char *DNSQuestion(char *next, int nb, struct my_dns *dns)      //decode nb dns question 
{
    if ((dns->questab = malloc(sizeof(dns_question_t) * nb)) == NULL)
    {
        fprintf(stderr, "Error malloc\n");
        exit(1);
    }
    for (int i = 0; i < nb; i++)
    {
        dns->questab[i].name = next;

        next = PrintDNSName(next, NULL, dns->head);

        dns->questab[i].type = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->questab[i].class = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);

        printf(" %s \\", type[dns->questab[i].type]);
    }
    return next;
}

char *DNSAnswer(char *next, int nb, struct my_dns *dns)         //decode nb dns answer 
{
    if ((dns->anwsertab = malloc(sizeof(struct dns_answer) * nb)) == NULL)
    {
        fprintf(stderr, "Error malloc\n");
        exit(1);
    }
    for (int i = 0; i < nb; i++)
    {
        dns->anwsertab[i].qst.name = next;
        next = PrintDNSName(next, NULL, dns->head);

        printf(" ");

        dns->anwsertab[i].qst.type = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].qst.class = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].TTL = be32toh(*(uint32_t *)next);
        next += sizeof(uint32_t);

        dns->anwsertab[i].raw.length = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].raw.data = next;

        switch (dns->anwsertab[i].qst.type)
        {
        case 1:
            printf(" %s ", inet_ntoa(*(struct in_addr *)next));
            next += dns->anwsertab[i].raw.length;
            break;
        case 28:
            char buf[40];
            printf(" %s ", inet_ntop(AF_INET6, (void *)next, buf, 40));
            next += dns->anwsertab[i].raw.length;
            break;

        case 5:
            next = PrintDNSName(next, NULL, dns->head);
            break;
        default:
            printf(" %s Unimplemented so end \n \\", type[dns->anwsertab[i].qst.type]);
            return next;
        }
        printf(" %s \\", type[dns->anwsertab[i].qst.type]);
    }
    return next;
}

void VerboseDNS(struct trameinfo *t)
{
    struct my_dns *dns = (struct my_dns *)t->header_lv4;

    uint16_t flags = be16toh(dns->head->flags);

    WriteInBuf(t, "\n\t\t\t|DNS: ");

    if (t->verbose > 2)                 //Flags
    {
        WriteInBuf(t, "Othors Flags {");
        if (flags >> 10 & 1)
            WriteInBuf(t, "Authoritative ");
        if (flags >> 9 & 1)
            WriteInBuf(t, "Truncated ");
        if (flags >> 8 & 1)
            WriteInBuf(t, "Recursions Desired ");
        if (flags >> 7 & 1)
            WriteInBuf(t, "Recursions Available ");
    }
    else
    {
        WriteInBuf(t, "Flags {");
        if (flags >> 10 & 1)
            WriteInBuf(t, " AA");
        if (flags >> 9 & 1)
            WriteInBuf(t, " TC");
        if (flags >> 8 & 1)
            WriteInBuf(t, " RD");
        if (flags >> 7 & 1)
            WriteInBuf(t, " RA");
    }
    WriteInBuf(t, "}");

    WriteInBuf(t, ", Reply code %i", flags & 0b1111);       //Reply code decode
    if (t->verbose > 2)
        switch (flags & 0b1111)
        {
        case 0:
            WriteInBuf(t, " (No Error),");
            break;

        case 1:
            WriteInBuf(t, " (Format Error),");
            break;

        case 2:
            WriteInBuf(t, " (Server Faillure),");
            break;

        case 3:
            WriteInBuf(t, " (Name Error),");
            break;

        case 4:
            WriteInBuf(t, " (Not Implemented),");
            break;

        case 5:
            WriteInBuf(t, " (Refused),");
            break;

        case 6:
            WriteInBuf(t, " (YX Domain),");
            break;

        case 7:
            WriteInBuf(t, " (YX RR Set),");
            break;

        case 8:
            WriteInBuf(t, " (NX RR Set),");
            break;

        case 9:
            WriteInBuf(t, " (Not Auth),");
            break;

        case 10:
            WriteInBuf(t, " (Not Zone),");
            break;

        default:
            WriteInBuf(t, " (Unknow Error),");
        }
    else
        WriteInBuf(t, ",");

    if (t->verbose == 2)
        WriteInBuf(t, " QC =%i, ANC=%i, NSC=%i, ARC=%i ", be16toh(dns->head->qdcount), be16toh(dns->head->ancount), be16toh(dns->head->nscount), be16toh(dns->head->arcount));
    else
        WriteInBuf(t, " Question Count=%i, Answer Count=%i, Name Server Count=%i, Additional Record Count=%i ", be16toh(dns->head->qdcount), be16toh(dns->head->ancount), be16toh(dns->head->nscount), be16toh(dns->head->arcount));
    if (be16toh(dns->head->qdcount))
        WriteInBuf(t, "\n\t\t\t\t>");
    for (int i = 0; i < be16toh(dns->head->qdcount); i++)
    {
        if (t->verbose == 2)
            WriteInBuf(t, "Q%i C:%i, ", i + 1, dns->questab[i].class);

        else if (dns->questab[i].class == 1)
            WriteInBuf(t, "Query%i Class: IN, ", i + 1);
        else
            WriteInBuf(t, "Query%i Class: %i, ", i + 1, dns->questab[i].class);
    }
    if (be16toh(dns->head->ancount))

        WriteInBuf(t, "\n\t\t\t\t>");
    for (int i = 0; i < be16toh(dns->head->ancount); i++)
    {
        if (t->verbose == 2)
            WriteInBuf(t, "R%i C:%i TTL:%i, ", i + 1, dns->anwsertab[i].qst.class, dns->anwsertab[i].TTL);
        else if (dns->anwsertab[i].qst.class == 1)
            WriteInBuf(t, "Response%i Class: IN Time to Live:%i, ", i + 1, dns->anwsertab[i].TTL);
        else
            WriteInBuf(t, "Response%i Class: %i Time to Live:%i, ", i + 1, dns->anwsertab[i].qst.class, dns->anwsertab[i].TTL);
    }
}

int DecodeDNS(const u_char *packet, struct trameinfo *trameinfo)
{
    struct my_dns dns;

    trameinfo->header_lv4 = (void *)&dns;
    dns_header_t *head = (dns_header_t *)packet;

    dns.head = head;

    printf("%sDNS%s ", MAGENTA, RESET);
    if (trameinfo->verbose > 1)
        printf("(%s%x) ", (trameinfo->verbose > 2) ? "id: " : "", be16toh(head->xid));

    uint16_t flags = be16toh(head->flags);

    printf("\%s", GREEN);
    switch (flags >> 11 & 0b1111)
    {
    case 0:
        printf("Standart query ");
        break;

    case 1:
        printf("Iquery ");
        break;

    case 2:
        printf("Status ");
        break;

    case 3:
        printf("Reserved ??? ");
        break;

    case 4:
        printf("Notify ");
        break;

    case 5:
        printf("Update ");
        break;

    default:
        printf("?");
        break;
    }
    if ((flags) & (1 << 15))
        printf("Reponse ");

    printf("%s", RESET);
    if (flags & 0b01111)
        printf("%sreply error%s ", RED, RESET);

    char *next = DNSQuestion((char *)(packet + sizeof(*head)), be16toh(head->qdcount), &dns);

    if (be16toh(head->ancount))
        printf("/\\ "); // Show response start
    next = DNSAnswer(next, be16toh(head->ancount), &dns);

    (void)next;

    if (trameinfo->verbose > 1)
        VerboseDNS(trameinfo);
    return 0;
}