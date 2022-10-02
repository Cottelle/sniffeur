#include "dhcp.h"


void DHCPnames_reso(int code, char *buf)
{
    switch (code)
    {
    case 1:
        strcpy(buf, "mask");
        break;
    case 2:
        strcpy(buf, "time offset");
        break;
    case 3:
        strcpy(buf, "router");
        break;
    case 6:
        strcpy(buf, "DNS");
        break;
    case 12:
        strcpy(buf, "host name");
        break;
    case 15:
        strcpy(buf, "domain name");
        break;
    case 28:
        strcpy(buf, "brocast addr");
        break;
    case 44:
        strcpy(buf, "netbios server");
        break;
    case 47:
        strcpy(buf, "netbios scope");
        break;
    case 51:
        strcpy(buf, "lease time");
        break;
    case 54:
        strcpy(buf, "server id");
        break;
    case 61:
        strcpy(buf, "client id");
        break;
    default:
        // snprintf(buf,16, "Unreconized %i",code);
        snprintf(buf,16, "U%i",code);
        break;
    }
    return;
}



void PrintDHCP(struct dhcps dhcps[64],int verbose)
{
    if (verbose >2)
    {
        printf("\n|Decode DHCP: ");
        char name[16];
        for (int i=0; i<64;i++)
            if (dhcps[i].present)
            {
                DHCPnames_reso(i,name);
                if (i ==1 ||i ==3 ||i==28 ||i==54|| i==61)
                    printf("%s= %s ",name,inet_ntoa(*(struct in_addr *)(dhcps[i].str)));
            }
    }
    
}