
#include "my_smtp.h"

void PrintSMTP(const u_char *packect, struct trameinfo *t)
{
    int max = 10 * (t->verbose == 2) + 100 * (t->verbose == 3) + (-1) * (t->verbose > 3);
    WriteInBuf(t, "| SMTP message (%i %i %i)=\n ", max,t->len,t->cur);
    for (int i = 0, j = 0; i != max; j++)
    {
        if (packect[j]==0xd && packect[j+1]==0xa)
            break;
        if (isprint(packect[j]) || packect[j] == '\n')
        {
            WriteInBuf(t, "%c", packect[j]);
            i++;
        }
    }
}

int DecodeSMTP(const u_char *packect, struct trameinfo *trameinfo)
{
    printf(" SMTP  ");
    printf("ok\n");

    PrintSMTP(packect, trameinfo);

    return 0;
}
