#include "my_dhcp.h"


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
        snprintf(buf, 16, "U%i", code);
        break;
    }
    return;
}

void PrintDHCP(struct dhcp dhcps[64], struct trameinfo *t)
{
    char name[16];
    if (t->verbose > 2)
    {
        printf("\n|Decode DHCP: ");
        for (int i = 0; i < 64; i++)
            if (dhcps[i].present)
            {
                DHCPnames_reso(i, name);
                printf("%s= ", name);
                if (i == 1 || i == 3 || i == 28 || i == 54 || i == 61)
                    printf("%s ", inet_ntoa(*(struct in_addr *)(dhcps[i].str)));
                else if (i == 12 || i == 15)
                    printf("%s ", dhcps[i].str);
                else if (i == 2 || i == 44 || i == 47 || i == 51) // a peut être verifier
                {
                    unsigned long long sum = 0;
                    for (int j = 0; j < dhcps[i].size; j++)
                        sum += dhcps[i].str[j] << (dhcps[i].size - j - 1) * 8;
                    printf("%lli ", sum);
                }
                else if (i == 6) // DNS
                {
                    if (dhcps[i].size % 4 != 0)
                    {
                        printf("IP no 4(%i)", dhcps[i].size);
                        continue;
                    }
                    int nub = dhcps[i].size / 4;
                    for (int j = 0; j < nub; j++)
                        printf("%s ", inet_ntoa(*(struct in_addr *)(dhcps[i].str + j * 4)));
                }
            }
    }
    else // verbose ==2
    {
        printf("|Decode DHCP: ");
        for (int i = 0; i < 64; i++)
            if (dhcps[i].present)
            {

                if (i == 1 || i == 54 || i == 61)
                {
                    DHCPnames_reso(i, name);
                    printf("%s= ", name);
                    printf(" %s ", inet_ntoa(*(struct in_addr *)(dhcps[i].str)));
                }
                else if (i == 15)
                {
                    DHCPnames_reso(i, name);
                    printf("%s= ", name);
                    printf(" %s ", dhcps[i].str);
                }
            }
    }
}

void DecodeDHCP(const u_char *vend, struct trameinfo *trameinfo)
{
    printf("DHCP ");
    int i = 0;
    struct dhcp dhcps[64];
    memset(dhcps, 0, 64 * sizeof(struct dhcp));
    while (vend[i] != 0xff)
    {
        dhcps[vend[i]].str = vend + i + 2; // evite de faire une structure, alege le code au detriment de la mémoire.
        dhcps[vend[i]].size = vend[i + 1];
        dhcps[vend[i]].present = 1;
        i += vend[i + 1] + 2;
    }
    if (dhcps[53].present) //
        switch (dhcps[53].str[0])
        {
        case 1:
            printf("discover ");
            break;
        case 2:
            printf("offer ");
            break;

        case 3:
            printf("request ");
            if (dhcps[50].present)
                printf(": %s", inet_ntoa(*(struct in_addr *)(dhcps[50].str)));
            break;

        case 5:
            printf("ack ");
            break;

        case 7:
            printf("release ");
            break;

        default:
            printf("Unreconized %i op ", dhcps[53].str[0]);
            break;
        }
    if (dhcps[55].present)
    {
        printf(" req list =[");
        char name[16];
        for (char i = 0; i < dhcps[55].size; i++)
        {
            DHCPnames_reso(dhcps[55].str[(int)i], name);
            printf("%s,", name);
        }
        printf("]");
    }
    if (trameinfo->verbose > 1)
        PrintDHCP(dhcps, trameinfo);
}
