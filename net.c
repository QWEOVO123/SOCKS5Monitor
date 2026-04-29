#pragma comment(lib,"ws2_32.lib")

#include "net.h"
#include <ws2tcpip.h>
#include <stdio.h>

/* ================= init ================= */

int net_init()
{
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

/* ================= close ================= */

void net_close(SOCKET s)
{
    if (s != INVALID_SOCKET)
        closesocket(s);
}

/* ================= connect ================= */

SOCKET net_tcp_connect(const char* host, int port)
{
    SOCKET s = INVALID_SOCKET;

    struct addrinfo hints;
    struct addrinfo* result = NULL;

    char portstr[16];
    sprintf_s(portstr, sizeof(portstr), "%d", port);

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, portstr, &hints, &result) != 0)
        return INVALID_SOCKET;

    struct addrinfo* ptr;

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        s = socket(ptr->ai_family,
            ptr->ai_socktype,
            ptr->ai_protocol);

        if (s == INVALID_SOCKET)
            continue;

        if (connect(s, ptr->ai_addr,
            (int)ptr->ai_addrlen) == 0)
            break;

        closesocket(s);
        s = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return s;
}