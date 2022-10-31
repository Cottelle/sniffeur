#include "my_dns.h"

// /**
//  * @brief Print the TCP flags
//  */
// void PrintTCPFlags(uint8_t th_flags);

void PrintDNS(struct trameinfo *t)
{
    dns_header_t *dns = (dns_header_t *)t->header_lv4;

    WriteInBuf(t, "\n\t\t\tDecode DNS: ");

    if (t->verbose > 2)
    {
        WriteInBuf(t, "Othors Flags {");
        if (dns->flags >> 10 & 1)
            WriteInBuf(t, "Authoritative ");
        if (dns->flags >> 9 & 1)
            WriteInBuf(t, "Truncated ");
        if (dns->flags >> 8 & 1)
            WriteInBuf(t, "Recursions Desired ");
        if (dns->flags >> 7 & 1)
            WriteInBuf(t, "Recursions Available ");
    }
    else
    {
        WriteInBuf(t, "Flags {");
        if (dns->flags >> 10 & 1)
            WriteInBuf(t, " AA");
        if (dns->flags >> 9 & 1)
            WriteInBuf(t, " TC");
        if (dns->flags >> 8 & 1)
            WriteInBuf(t, " RD");
        if (dns->flags >> 7 & 1)
            WriteInBuf(t, " RA");
    }
    WriteInBuf(t, "}");

    WriteInBuf(t, ", Reply code %i", dns->flags & 0b1111);
    if (t->verbose > 2)
        switch (dns->flags & 0b1111)
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
        WriteInBuf(t,",");

    if (t->verbose == 2)
        WriteInBuf(t, " QC =%i, ANC=%i, NSC=%i, ARC=%i ", dns->qdcount, dns->ancount, dns->nscount, dns->arcount);
    else
        WriteInBuf(t, " Question Count=%i, Answer Count=%i, Name Server Count=%i, Additional Record Count=%i ", dns->qdcount, dns->ancount, dns->nscount, dns->arcount);

    (void)dns;
}

int DecodeDNS(const u_char *packet, struct trameinfo *trameinfo)
{
    trameinfo->header_lv4 = (void *)packet;
    dns_header_t *dns = (dns_header_t *)packet;

    printf("DNS\33[00m");
    printf("(%s%x) ", (trameinfo->verbose > 1) ? "id: " : "", dns->xid);

    switch ((dns->flags) >> 11 & 0b1111)
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
    if ((dns->flags) & 1 << 15)
        printf("Reponse ");
    if (dns->flags & 0b1111)
        printf("reply error ");
    
    printf("%s",packet+sizeof(dns_header_t));

    PrintDNS(trameinfo);
    return 0;
}