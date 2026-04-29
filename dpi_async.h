#pragma once
#ifndef DPI_ASYNC_H
#define DPI_ASYNC_H

#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

    // 初始化异步 DPI 系统
    void dpi_async_init(int worker_count);

    // 停止异步 DPI 系统
    void dpi_async_stop(void);

    // 异步投递数据（非阻塞）
    void dpi_async_submit(SOCKET client_sock, const char* client_ip,
        const unsigned char* data, int len, int dir);

#ifdef __cplusplus
}
#endif

#endif