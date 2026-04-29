#include "socks5.h"
#include "dpi.h"
#include "dpi_async.h"

// 外部变量声明
extern int g_dpi_async_mode; 
extern dpi_hook_fn g_dpi_hook;

void relay_loop(SOCKET client, SOCKET remote, const char* client_ip)
{
    char buf[BUFFER_SIZE];
    fd_set fds;
    int len;

    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(client, &fds);
        FD_SET(remote, &fds);

        if (select(0, &fds, NULL, NULL, NULL) <= 0)
            break;

        /* client -> remote */
        if (FD_ISSET(client, &fds))
        {
            len = recv(client, buf, BUFFER_SIZE, 0);
            if (len <= 0) break;

            if (g_dpi_async_mode) {
                // 异步模式：先转发，后投递
                send(remote, buf, len, 0);
                dpi_async_submit(client, client_ip, (unsigned char*)buf, len, 0);
            }
            else {
                // 同步模式：先检测，后转发
                if (g_dpi_hook) g_dpi_hook(client, client_ip, buf, len, 0);
                send(remote, buf, len, 0);
            }
        }

        /* remote -> client */
        if (FD_ISSET(remote, &fds))
        {
            len = recv(remote, buf, BUFFER_SIZE, 0);
            if (len <= 0) break;

            if (g_dpi_async_mode) {
                // 异步模式：先转发，后投递
                send(client, buf, len, 0);
                dpi_async_submit(client, client_ip, (unsigned char*)buf, len, 1);
            }
            else {
                // 同步模式：先检测，后转发
                if (g_dpi_hook) g_dpi_hook(client, client_ip, buf, len, 1);
                send(client, buf, len, 0);
            }
        }
    }
}