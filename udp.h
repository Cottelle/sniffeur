#define L_SRCPORT 16
#define L_DSTPORT 16
#define L_LGTH 16
#define L_SUM 16

struct udp
{
    unsigned int S_Port : L_SRCPORT;
    unsigned int D_Port : L_DSTPORT;
    unsigned int Length : L_LGTH;
    unsigned int Sum : L_SUM;
};
