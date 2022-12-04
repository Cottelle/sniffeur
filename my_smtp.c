
#include "my_smtp.h"

void PrintSMTP(const u_char *packect, struct trameinfo *t)
{
    int max = 10 * (t->verbose == 2) + 100 * (t->verbose == 3) + (-1) * (t->verbose > 3);
    WriteInBuf(t, "| SMTP message (%i %i %i)=\n ", max, t->len, t->cur);
    for (int i = 0, j = 0; i != max; j++)
    {
        if (packect[j] == 0xd && packect[j + 1] == 0xa)
            break;
        if (isprint(packect[j]) || packect[j] == '\n')
        {
            WriteInBuf(t, "%c", packect[j]);
            i++;
        }
        else if (!isprint(packect[j]))
        {
            WriteInBuf(t, ".");
            i++;
        }
    }
}

int DecodeSMTP(const u_char *packect, struct trameinfo *trameinfo)
{
    printf("%sSMTP%s  ",MAGENTA,RESET);

    if (trameinfo->verbose > 1)
        PrintSMTP(packect, trameinfo);

    return 0;
}
