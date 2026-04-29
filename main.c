#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ws2_32.lib")

#include "socks5.h"
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dpi.h"
#include "banner.h"
#include "tls_flow.h"
#include "conn_tracker.h"
#include "dpi_async.h"

// 导出给 relay.c 使用
int g_dpi_async_mode = 0;

int main(int argc, char* argv[])
{
    banner_show();
	printf("正在初始化...");
    int worker_count = 2;    // 默认工作线程数

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--async") == 0 || strcmp(argv[i], "-a") == 0) {
            g_dpi_async_mode = 1;
            worker_count = 2;
        }
        else if (strncmp(argv[i], "--async=", 8) == 0) {
            g_dpi_async_mode = 1;
            worker_count = atoi(argv[i] + 8);
            if (worker_count < 1) worker_count = 1;
            if (worker_count > 8) worker_count = 8;
        }
    }

    net_init();
    tls_flow_init();
    dpi_sync_init();
    conn_tracker_init();

    if (g_dpi_async_mode) {
        dpi_async_init(worker_count);
    }

    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 128);

    printf("SOCKS5已经在%d上开放\n",DEFAULT_PORT);

    while (1)
    {
        SOCKET client = accept(server, NULL, NULL);
        CreateThread(NULL, 0, socks5_handle_client, (LPVOID)client, 0, NULL);
    }

    if (g_dpi_async_mode) {
        dpi_async_stop();
    }
    conn_tracker_cleanup();
    return 0;
}