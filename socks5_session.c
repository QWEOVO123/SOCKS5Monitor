#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "socks5.h"
#include "net.h"
#include "conn_tracker.h"
#include <stdio.h>
#include <ws2tcpip.h>

extern void banner_show(void);
extern void dpi_sync_init(void);
extern void tls_flow_cleanup(int flow_id);

int socks5_handshake(SOCKET);
int socks5_parse_request(SOCKET, char*, int*);
void socks5_send_reply(SOCKET, int);
void relay_loop(SOCKET, SOCKET, const char*);

static void get_client_ip(SOCKET client, char* ip_buf, int buf_size)
{
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);

    if (getpeername(client, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &(addr.sin_addr), ip_buf, buf_size);
    }
    else {
        strcpy_s(ip_buf, buf_size, "unknown");
    }
}

DWORD WINAPI socks5_handle_client(LPVOID arg)
{
    socks5_session session;
    session.client = (SOCKET)arg;
    session.remote = INVALID_SOCKET;

    get_client_ip(session.client, session.client_ip, sizeof(session.client_ip));

    // 跟踪连接，决定是否输出日志
    int show_connect = conn_track_connect(session.client_ip);
    if (show_connect) {
        printf("[SOCKS5] 检测到用户从%s接入\n", session.client_ip);
    }

    if (socks5_handshake(session.client) != 0)
        goto end;

    if (socks5_parse_request(
        session.client,
        session.host,
        &session.port) != 0)
        goto end;

    // 只在有新连接时输出目标信息
    if (show_connect) {
        printf("[SOCKS5] %s -> %s:%d\n", session.client_ip, session.host, session.port);
    }

    session.remote = net_tcp_connect(session.host, session.port);

    if (session.remote == INVALID_SOCKET)
    {
        socks5_send_reply(session.client, SOCKS5_HOST_UNREACHABLE);
        goto end;
    }

    socks5_send_reply(session.client, SOCKS5_SUCCESS);

    relay_loop(session.client, session.remote, session.client_ip);

end:
    // 记录断开
    conn_track_disconnect(session.client_ip);

    tls_flow_cleanup((int)session.client);
    net_close(session.remote);
    net_close(session.client);
    return 0;
}