#include "my_http.h"

void VerboseHTTP(struct trameinfo *t)
{
    if ((int)(t->len - t->cur) <= 0)
        return;
    WriteInBuf(t, "\n\t\t\t|HTTP:\n ");
    const u_char *http = (const u_char *)t->header_lv4;
    for (int i = 0; i < (int)(t->len - t->cur) && (http[i] != '\n' || t->verbose == 3); i++)
    {
        if (isprint(http[i]))
            WriteInBuf(t, "%c", http[i]);
        else
            WriteInBuf(t, ".");
    }
}

int DecodeHTTP(const u_char *packet, struct trameinfo *trameinfo)
{
    printf("%sHTTP%s", MAGENTA, RESET);
    trameinfo->header_lv4 = (void *)packet;
    if (trameinfo->verbose > 1)
        VerboseHTTP(trameinfo);

    return 0;
}
