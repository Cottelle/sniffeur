#include "trameinfo.h"

char *INT2MAC(uint8_t *val, char *buf)
{
    snprintf(buf, 1024, "%x:%x:%x:%x:%x:%x", val[0], val[1], val[2], val[3], val[4], val[5]);
    return buf;         //for easy print
}


void WriteInBuf(struct trameinfo *t, char *format, ...)
{
    int i;
    va_list ap;
    va_start(ap,format);

    while ((i = vsnprintf(t->bufverbose, 0, format, ap)) + t->write_buf >= t->size_buf) //test si il y a de la place. Crer de la place sinon
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
    va_start(ap,format);
    if (i == -1 || (i=vsnprintf(t->bufverbose + t->write_buf, t->size_buf - t->write_buf, format, ap)) == -1)
    {
        fprintf(stderr,"snprintf error");
        exit(2);
    }
    t->write_buf+=i;
}


void SyntheseIP(struct ip *ip, int SP, int DP, char color)
{

    printf("\33[%im%s\33[00m:\33[%im%i\33[00m", BLUE(color), inet_ntoa(ip->ip_src), YELLOW(color), SP);
    printf(" --> \33[%im%s\33[00m:\33[%im%i\33[00m \33[%im%s\33[00m", BLUE(color), inet_ntoa(ip->ip_dst), YELLOW(color), DP, RED(color), (ip->ip_p == 0x11) ? "UDP " : ((ip->ip_p == 0x06) ? "TCP" : "??"));

}