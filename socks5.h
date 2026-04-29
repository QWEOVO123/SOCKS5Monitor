#ifndef SOCKS5_H
#define SOCKS5_H

#include <winsock2.h>

/* ================= CONFIG ================= */

#define BUFFER_SIZE 8192
#define SOCKS5_VERSION 0x05
#define DEFAULT_PORT 1080

/* ================= RESPONSE ================= */

#define SOCKS5_SUCCESS 0x00
#define SOCKS5_GENERAL_FAILURE 0x01
#define SOCKS5_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_NETWORK_UNREACHABLE 0x03
#define SOCKS5_HOST_UNREACHABLE 0x04
#define SOCKS5_CONNECTION_REFUSED 0x05
#define SOCKS5_TTL_EXPIRED 0x06
#define SOCKS5_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* ================= ADDRESS ================= */

#define ADDRESS_TYPE_IPV4   0x01
#define ADDRESS_TYPE_DOMAIN 0x03
#define ADDRESS_TYPE_IPV6   0x04

/* ================= COMMAND ================= */

#define COMMAND_CONNECT 0x01
#define COMMAND_BIND    0x02
#define COMMAND_UDP     0x03

/* ================= STRUCT ================= */

typedef struct
{
    SOCKET client;
    SOCKET remote;

    char host[256];
    int port;

    char client_ip[64];  //客户端 IP 地址

} socks5_session;

/* ================= API ================= */

DWORD WINAPI socks5_handle_client(LPVOID arg);
void relay_loop(SOCKET client, SOCKET remote, const char* client_ip);
// relay_loop 函数声明
void relay_loop(SOCKET client, SOCKET remote, const char* client_ip);

#endif