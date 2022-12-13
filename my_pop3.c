#include "my_pop3.h"

void VerbosePOP3(struct trameinfo *t)
{
    if ((int)(t->len - t->cur) <= 0)
        return;
    WriteInBuf(t, "\n\t\t\t|POP3:\n ");
    const u_char *pop3 = (const u_char *)t->header_lv4;
    for (int i = 0; i < (int)(t->len - t->cur) && (pop3[i] != '\n' || t->verbose == 3); i++)
    {
        if (isprint(pop3[i]))
            WriteInBuf(t, "%c", pop3[i]);
        else
            WriteInBuf(t, ".");
    }
}

int DecodePOP3(const u_char *packet, struct trameinfo *trameinfo)
{
    printf("%sPOP3%s", MAGENTA, RESET);
    trameinfo->header_lv4 = (void *)packet;
    if (trameinfo->verbose > 1)
        VerbosePOP3(trameinfo);

    return 0;
}
