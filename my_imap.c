#include "my_imap.h"

void VerboseIMAP(struct trameinfo *t)
{
    if ((int)(t->len - t->cur) <= 0)
        return;
    WriteInBuf(t, "\n\t\t\t|IMAP:\n ");
    const u_char *imap = (const u_char *)t->header_lv4;
    for (int i = 0; i < (int)(t->len - t->cur) && (imap[i] != '\n' || t->verbose == 3); i++)
    {
        if (isprint(imap[i]))
            WriteInBuf(t, "%c", imap[i]);
        else
            WriteInBuf(t, ".");
    }
}

int DecodeIMAP(const u_char *packet, struct trameinfo *trameinfo)
{
    printf("%sIMAP%s", MAGENTA, RESET);
    trameinfo->header_lv4 = (void *)packet;
    if (trameinfo->verbose > 1)
        VerboseIMAP(trameinfo);

    return 0;
}
