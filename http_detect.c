#include <stdio.h>
#include <string.h>
#include "dpi.h"
#include "http_parser.h"

void parse_http(const char* data, int len, const char* client_ip)
{
    if (len < 16) return;

    /* ÕÒ Host: */
    const char* host = strstr(data, "Host:");
    if (host)
    {
        host += 5;
        while (*host == ' ') host++;

        char domain[256] = { 0 };
        int i = 0;

        while (*host && *host != '\r' && *host != '\n' && i < 255)
            domain[i++] = *host++;

        domain[i] = '\0';

        printf("[HTTP¼ì²â] %s -> %s\n", client_ip, domain);
    }
}