#ifndef MYDNS
#define MYDNS

#include "dns_apple.h"
#include "trameinfo.h"

struct dns_answer
{
    dns_question_t qst;
    uint32_t TTL;
    dns_raw_resource_record_t raw;
};

struct my_dns
{
    dns_header_t *head;
    dns_question_t *questab;
    struct dns_answer *anwsertab;

    dns_address_record_t *addrtab;
    dns_in6_address_record_t *addr6tab;
    dns_domain_name_record_t *nametab;
};


/**
 * @brief Print the TCP info depence of verbose level into verbose buffer
 */
void PrintDNS(struct trameinfo* t);

/**
 * @brief Decode DNS trame since packet
 */
int DecodeDNS(const u_char *packet, struct trameinfo *trameinfo);








#endif