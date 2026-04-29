#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include "socks5.h"
#include <stdio.h>

int socks5_handshake(SOCKET client)
{
    unsigned char buf[BUFFER_SIZE];

    int n = recv(client, (char*)buf, BUFFER_SIZE, 0);
    if (n <= 0) return -1;

    if (buf[0] != SOCKS5_VERSION)
        return -1;

    unsigned char resp[2] = { SOCKS5_VERSION,0x00 };

    send(client, (char*)resp, 2, 0);
    return 0;
}

int socks5_parse_request(SOCKET client,
    char* host,
    int* port)
{
    unsigned char buf[BUFFER_SIZE];

    int n = recv(client, (char*)buf, BUFFER_SIZE, 0);
    if (n <= 0) return -1;

    if (buf[1] != COMMAND_CONNECT)
        return -1;

    int index = 4;

    switch (buf[3])
    {
    case ADDRESS_TYPE_IPV4:
        sprintf(host, "%u.%u.%u.%u",
            buf[index], buf[index + 1],
            buf[index + 2], buf[index + 3]);
        index += 4;
        break;

    case ADDRESS_TYPE_DOMAIN:
    {
        int len = buf[index++];
        memcpy(host, &buf[index], len);
        host[len] = 0;
        index += len;
        break;
    }

    default:
        return -1;
    }

    *port = (buf[index] << 8) | buf[index + 1];

    return 0;
}

void socks5_send_reply(SOCKET client, int code)
{
    unsigned char resp[10] = {
        SOCKS5_VERSION,
        code,
        0x00,
        ADDRESS_TYPE_IPV4,
        0,0,0,0,0,0
    };

    send(client, (char*)resp, 10, 0);
}