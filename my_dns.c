#include "my_dns.h"

// /**
//  * @brief Print the TCP flags
//  */
// void PrintTCPFlags(uint8_t th_flags);

char *(type)[] = {
    [1] "A",
    [28] "AAAA",
    [18] "AFSDB",
    [12] "PTR",
    [6]  "SOA",
    [5]  "CNAME",
};

char *PrintDNSName(char *name, struct trameinfo *t)
{
    int size = *name, first = 1;
    while ((size = *name) != 0)
    {
        if (first)
            first = 0;
        else
        {
            if (!t)
                printf(".");
            else
                WriteInBuf(t, ".");
        }
        name++;
        for (int i = 0; i < size; i++, name++)
        {
            if (!t)
                printf("%c", *name);
            else
                WriteInBuf(t, "%c", *name);
        }
    }
    return name + 1;
}
char *DNSQuestion(char *next, int nb, struct my_dns *dns)
{
    if ((dns->questab = malloc(sizeof(dns_question_t) * nb)) == NULL)
    {
        fprintf(stderr, "Error malloc\n");
        exit(1);
    }
    for (int i = 0; i < nb; i++)
    {
        dns->questab[i].name = next;

        next = PrintDNSName(next, NULL);

        dns->questab[i].type = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->questab[i].class = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);

        printf(" %s \\", type[dns->questab[i].type]);
    }
    return next;
}

char *DNSAnswer(char *next, int nb, struct my_dns *dns)
{
    if ((dns->anwsertab = malloc(sizeof(struct dns_answer) * nb)) == NULL)
    {
        fprintf(stderr, "Error malloc\n");
        exit(1);
    }
    for (int i = 0; i < nb; i++)
    {
        dns->anwsertab[i].qst.name = next;

        next += 2;

        dns->anwsertab[i].qst.type = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].qst.class = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].TTL = be32toh(*(uint32_t *)next);
        next += sizeof(uint32_t);

        dns->anwsertab[i].raw.length = be16toh(*(uint16_t *)next);
        next += sizeof(uint16_t);
        dns->anwsertab[i].raw.data = next;

        switch(dns->anwsertab[i].qst.type)
        {
        case 1:
            printf(" %s ", inet_ntoa(*(struct in_addr *)next));
            next += dns->anwsertab[i].raw.length;
            break;
        case 28:
        //     char buf[128];
        //     printf(" %s ", inet_ntop(AF_INET6, next, buf, 1024));
        printf("IP6 Addr");
            break;

        default:
            next = PrintDNSName(next, NULL);
        }
        printf(" %s \\", type[dns->anwsertab[i].qst.type]);
    }
    return next;
}

void PrintDNS(struct trameinfo *t)
{
    struct my_dns *dns = (struct my_dns *)t->header_lv4;

    uint16_t flags = be16toh(dns->head->flags);

    WriteInBuf(t, "\n\t\t\tDecode DNS: ");

    if (t->verbose > 2)
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

    WriteInBuf(t, ", Reply code %i", flags & 0b1111);
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

    (void)dns->head;
}

int DecodeDNS(const u_char *packet, struct trameinfo *trameinfo)
{
    struct my_dns dns;

    trameinfo->header_lv4 = (void *)&dns;
    dns_header_t *head = (dns_header_t *)packet;

    dns.head = head;

    printf("%sDNS%s", MAGENTA, RESET);
    printf("(%s%x) ", (trameinfo->verbose > 1) ? "id: " : "", be16toh(head->xid));

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

    next = DNSAnswer(next, be16toh(head->ancount), &dns);

    (void)next;

    if (trameinfo->verbose > 1)
        PrintDNS(trameinfo);
    return 0;
}