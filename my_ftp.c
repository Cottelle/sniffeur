#include "my_ftp.h"

void VerboseFTP(struct trameinfo *t, int list)
{
    if ((int)(t->len - t->cur) <= 0)
        return;
    WriteInBuf(t, "\n\t\t\t|FTP: ");
    if (list)
    {
        WriteInBuf(t, "\n");
        const u_char *ftp = (const u_char *)t->header_lv4;

        for (int i = 0; i < (int)(t->len - t->cur) && (ftp[i] != '\n' || t->verbose == 3); i++)
        {
            if (isprint(ftp[i]))
                WriteInBuf(t, "%c", ftp[i]);
            else
                WriteInBuf(t, ".");
        }
    }
    else
        WriteInBuf(t, " %i bytes of data\n ");
}

int DecodeFTP(const u_char *packet, struct trameinfo *trameinfo, int list)
{
    printf("%sFTP", MAGENTA);
    if (list)
        printf(" LISTENING%s", RESET);
    else
        printf(" TRANSFERT%s", RESET);

    trameinfo->header_lv4 = (void *)packet;

    if (trameinfo->verbose > 1)
        VerboseFTP(trameinfo, list);
    return 0;
}