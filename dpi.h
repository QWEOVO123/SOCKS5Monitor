#ifndef DPI_H
#define DPI_H

#include <winsock2.h>

typedef void (*dpi_hook_fn)(
    SOCKET client_sock,
    const char* client_ip,
    const char* data,
    int len,
    int direction
    );

/* global hook */
extern dpi_hook_fn g_dpi_hook;

/* 设置钩子 */
void dpi_set_hook(dpi_hook_fn hook);

/* 初始化同步 DPI 检测（设置默认钩子） */
void dpi_sync_init(void);

#endif