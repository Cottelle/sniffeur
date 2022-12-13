
#include "my_smtp.h"

void VerboseSMTP(struct trameinfo *t)
{
    const u_char *smtp = (const u_char *)t->header_lv4;

    if ((int)(t->len - t->cur) <= 0)
        return;
    WriteInBuf(t, "\n\t\t\t|SMTP:\n ");
    for (int i = 0; i < (int)(t->len - t->cur) && (smtp[i] != '\n' || t->verbose == 3); i++)
    {
        if (isprint(smtp[i]))
            WriteInBuf(t, "%c", smtp[i]);
        else
            WriteInBuf(t, ".");
    }
}

int DecodeSMTP(const u_char *packect, struct trameinfo *trameinfo)
{
    printf("%sSMTP%s  ", MAGENTA, RESET);
    trameinfo->header_lv4 = (void *)packect;
    if (trameinfo->verbose > 1)
        VerboseSMTP(trameinfo);

    return 0;
}
