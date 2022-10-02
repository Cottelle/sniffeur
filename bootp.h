#define HEADER_LEN 44   //Octet
#define SNAME_LEN 64   //Octet
#define FILE_LEN 128     //Octet
//vend has no size beaucause it can be extended



struct bootp
{
    unsigned char op:8;
    unsigned char htype:8;
    unsigned char hlen:8;
    unsigned char hops:8;

    unsigned int xid:32;

    unsigned int secs:16;
    unsigned int flags:16;

    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    unsigned int chaddr[16];

    const u_char *sname;
    const u_char *file;
    const uint16_t *vend;

};
