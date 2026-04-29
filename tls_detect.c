#include <stdio.h>
#include <string.h>
#include "dpi.h"
#include "tls_parser.h"
//≤‚ ‘”√£¨ºÏ≤‚TLSŒ’ ÷
void parse_tls_sni(const unsigned char* data, int len)
{
    printf("[TLS RAW] len=%d first=%02X %02X %02X\n",
        len,
        data[0], data[1], data[2]);

    if (len < 5) return;

    if (data[0] != 0x16)
        return;

    printf("[TLS] ºÏ≤‚µΩŒ’ ÷\n");
}