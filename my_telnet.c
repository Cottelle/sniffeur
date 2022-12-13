#include "my_telnet.h"

void VerboseTELNET(struct trameinfo *t)
{
    WriteInBuf(t, "\n\t\t\t|TELNET: \n");
    if (t->len - t->cur <= 0)
        return;
    const u_char *telnet = (const u_char *)t->header_lv4;
    if (telnet[0] == EXOPL)
    {
        int sb = 0;
        for (unsigned int i = 0; i < t->len - t->cur; i++)
        {
            if (sb > 0)     //Ne dois pas être interpreter comme des codes
            {
                if (telnet[i] != IAC)
                {
                    WriteInBuf(t, "%i ", telnet[i]);
                    continue;
                }
            }
            switch (telnet[i])
            {
            case TERMINAL_TYPE:
                WriteInBuf(t, "TERMINAL_TYPE ");
                break;
            case NAWS:
                WriteInBuf(t, "NAWS ");
                break;
            case TS:
                WriteInBuf(t, "TS ");
                break;
            case ECHO:
                WriteInBuf(t, "ECHO ");
                break;
            case SUPPRESS_GO_AHEAD:
                WriteInBuf(t, "SUPPRESS_GO_AHEAD ");
                break;
            case TIMING_MARK:
                WriteInBuf(t, "TIMING_MARK ");
                break;
            case TERMINAL_SPEED:
                WriteInBuf(t, "TERMINAL_SPEED ");
                break;
            case REMOTE_FLOW_CONTROL:
                WriteInBuf(t, "REMOTE_FLOW_CONTROL ");
                break;
            case LINEMODE:
                WriteInBuf(t, "LINEMODE ");
                break;
            case X_DISPLAY_LOCATION:
                WriteInBuf(t, "X_DISPLAY_LOCATION ");
                break;
            case ENVIRONMENT_VARIABLE:
                WriteInBuf(t, "ENVIRONMENT_VARIABLE ");
                break;
            case AUTHENTICATION:
                WriteInBuf(t, "AUTHENTICATION ");
                break;
            case ENCRYPTION:
                WriteInBuf(t, "ENCRYPTION ");
                break;
            case NEW_ENVIRONMENT:
                WriteInBuf(t, "NEW_ENVIRONMENT ");
                break;
            case TN3270E:
                WriteInBuf(t, "TN3270E ");
                break;
            case XAUTH:
                WriteInBuf(t, "XAUTH ");
                break;
            case CHARSET:
                WriteInBuf(t, "CHARSET ");
                break;
            case RSP:
                WriteInBuf(t, "RSP ");
                break;
            case COM_PORT_CONTROL:
                WriteInBuf(t, "COM_PORT_OPTION ");
                break;
            case SUPPRESS_LOCAL_ECHO:
                WriteInBuf(t, "SUPPRESS_LOCAL_ECHO ");
                break;
            case START_TLS:
                WriteInBuf(t, "START_TLS ");
                break;
            case KERMIT:
                WriteInBuf(t, "KERMIT ");
                break;
            case SEND_URL:
                WriteInBuf(t, "SEND_URL ");
                break;
            case PRAGMA_LOGON:
                WriteInBuf(t, "PRAGMA_LOGON ");
                break;
            case SSPI_LOGON:
                WriteInBuf(t, "SSPI_LOGON ");
                break;
            case PRAGMA_HEARTBEAT:
                WriteInBuf(t, "PRAGMA_HEARTBEAT ");
                break;

            case SE:
                sb = 0;         //On sort de l'interpretation en nombre 
            case NOP:
                break;
            case DM:
                WriteInBuf(t, "DM ");
                break;
            case BRK:
                WriteInBuf(t, "BRK ");
                break;
            case IP:
                WriteInBuf(t, "IP ");
                break;
            case AO:
                WriteInBuf(t, "AO ");
                break;
            case AYT:
                WriteInBuf(t, "AYT ");
                break;
            case EC:
                WriteInBuf(t, "EC ");
                break;
            case EL:
                WriteInBuf(t, "EL ");
                break;
            case GA:
                WriteInBuf(t, "GA ");
                break;
            case SB:
                WriteInBuf(t, ", ");
                sb = -1;        // le prochain sera -1 donc interpreter comme un code puis -1*-1 >0: le reste comme des nombres
                continue;
            case WILL:
                WriteInBuf(t, ", WILL ");
                break;
            case WONT:
                WriteInBuf(t, ", WONT ");
                break;
            case DO:
                WriteInBuf(t, ", DO ");
                break;
            case DONT:
                WriteInBuf(t, ", DONT ");
                break;
            case IAC:
                sb = 0;
                continue;
            default:
                WriteInBuf(t, "%i ", telnet[i]);
                break;
            }
            if (sb==-1)
                WriteInBuf(t,"=");
            sb = sb * sb;               //(0*0 <=0 -1*-1 >0 )
        }
    }
    else
    {
        WriteInBuf(t, "Data:");
        for (unsigned int i = 0; i < t->len - t->cur; i++)
            WriteInBuf(t, "%c", telnet[i]);
    }
}

int DecodeTELNET(const u_char *packet, struct trameinfo *trameinfo)
{
    trameinfo->header_lv4 = (void *)packet;
    printf("%sTELNET %s", MAGENTA, RESET);
    if (*packet == 0xff)
        printf("Negociation");
    else
        printf("data");
    if (trameinfo->verbose > 1)
        VerboseTELNET(trameinfo);
    return 0;
}
