#include "trameinfo.h"

char *GREEN = "\33[32m";
char *BLUE = "\33[34m";
char *RED = "\33[31m";
char *YELLOW = "\33[33m";
char *MAGENTA = "\33[35m";
char *CYAN = "\33[36m";
char *WHITE = "\33[37m";
char *BLACK = "\33[30m";
char *RESET = "\33[00m";

char *INT2MAC(uint8_t *val, char *buf)
{
    snprintf(buf, 1024, "%x:%x:%x:%x:%x:%x", val[0], val[1], val[2], val[3], val[4], val[5]);
    return buf; // for easy print
}

void WriteInBuf(struct trameinfo *t, char *format, ...)
{
    int i;
    va_list ap;
    va_start(ap, format);

    while ((i = vsnprintf(t->bufverbose, 0, format, ap)) + t->write_buf >= t->size_buf) // test si il y a de la place. Crer de la place sinon
    {
        t->size_buf *= 2;
        t->bufverbose = realloc(t->bufverbose, t->size_buf);
        if (!t->bufverbose)
        {
            fprintf(stderr, "realloc failed");
            exit(1);
        }
    }
    va_end(ap);
    va_start(ap, format);
    if (i == -1 || (i = vsnprintf(t->bufverbose + t->write_buf, t->size_buf - t->write_buf, format, ap)) == -1)
    {
        fprintf(stderr, "snprintf error");
        exit(2);
    }
    t->write_buf += i;
}


void SyntheseIP(struct trameinfo *t, int SP, int DP)
{
    char buf[50],*src,*dst;
    if (t->Ipv==AF_INET6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr*)t->header_lv2;
        src = (char *)&(ip6->ip6_src);
        dst = (char *)&(ip6->ip6_dst);
    }
    else if (t->Ipv==AF_INET)
    {
        struct ip *ip = t->header_lv2;
        src = (char *)&(ip->ip_src);
        dst = (char *)&(ip->ip_dst);
    }
    else
    {
        printf("Error Ipv not set\n continue\n");
        return;
    }

    printf("%s%s%s>%s%i%s", BLUE, inet_ntop(t->Ipv,src,buf,50), RESET, YELLOW, SP, RESET);
    printf(" --> %s%s%s>%s%i%s ", BLUE, inet_ntop(t->Ipv,dst,buf,50), RESET, YELLOW, DP, RESET);
    // inet_ntop()
}
