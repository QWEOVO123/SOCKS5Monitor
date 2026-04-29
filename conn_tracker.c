#include "conn_tracker.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKED_IPS 256
#define CONN_TIMEOUT_SEC 10

typedef struct {
    char ip[64];
    time_t first_seen;
    time_t last_seen;
    int active_connections;
    int logged_connect;
    int logged_disconnect;
    int disconnect_reported;  // 0=未报告, 1=正常断开, 2=超时断开, 3=程序退出
} tracked_ip_t;

static tracked_ip_t tracked_ips[MAX_TRACKED_IPS];
static int tracked_count = 0;

// 全局临界区，保护 tracked_ips 和 tracked_count 的并发访问
static CRITICAL_SECTION g_tracker_lock;

#ifdef _WIN32
static int tracker_running = 0;
static HANDLE timeout_thread_handle = NULL;
#endif

// 内部函数：查找或创建 IP 记录（调用前必须已持有锁）
static tracked_ip_t* find_or_create_ip(const char* client_ip)
{
    time_t now = time(NULL);

    // 先查找已有记录
    for (int i = 0; i < tracked_count; i++) {
        if (strcmp(tracked_ips[i].ip, client_ip) == 0) {
            return &tracked_ips[i];
        }
    }

    // 清理超时的旧记录（active_connections == 0 且超时）
    for (int i = 0; i < tracked_count; ) {
        if (tracked_ips[i].active_connections == 0) {
            if (now - tracked_ips[i].last_seen > CONN_TIMEOUT_SEC) {
                if (tracked_ips[i].disconnect_reported == 0) {
                    printf("[SOCKS5] %s 超时断开连接\n", tracked_ips[i].ip);
                    tracked_ips[i].disconnect_reported = 2;
                }
                // 移除记录：将最后一个元素移动到当前位置
                if (i < tracked_count - 1) {
                    tracked_ips[i] = tracked_ips[tracked_count - 1];
                }
                memset(&tracked_ips[tracked_count - 1], 0, sizeof(tracked_ip_t));
                tracked_count--;
                // 不增加 i，继续检查新移过来的元素
                continue;
            }
        }
        i++;
    }

    // 创建新记录
    if (tracked_count < MAX_TRACKED_IPS) {
        tracked_ip_t* tip = &tracked_ips[tracked_count];
        strcpy_s(tip->ip, sizeof(tip->ip), client_ip);
        tip->first_seen = now;
        tip->last_seen = now;
        tip->active_connections = 0;
        tip->logged_connect = 0;
        tip->logged_disconnect = 0;
        tip->disconnect_reported = 0;
        tracked_count++;
        return tip;
    }

    return NULL;
}

void conn_tracker_init(void)
{
    InitializeCriticalSection(&g_tracker_lock);

    EnterCriticalSection(&g_tracker_lock);
    memset(tracked_ips, 0, sizeof(tracked_ips));
    tracked_count = 0;
    LeaveCriticalSection(&g_tracker_lock);

#ifdef _WIN32
    tracker_running = 1;
    timeout_thread_handle = CreateThread(NULL, 0, timeout_checker_thread, NULL, 0, NULL);
#endif
}

void conn_tracker_cleanup(void)
{
#ifdef _WIN32
    tracker_running = 0;
    if (timeout_thread_handle) {
        WaitForSingleObject(timeout_thread_handle, 2000);
        CloseHandle(timeout_thread_handle);
        timeout_thread_handle = NULL;
    }
#endif

    EnterCriticalSection(&g_tracker_lock);

    time_t now = time(NULL);
    for (int i = 0; i < tracked_count; i++) {
        if (tracked_ips[i].active_connections > 0) {
            // 还有活跃连接，强制断开
            printf("[SOCKS5] %s 断开连接 (程序退出)\n", tracked_ips[i].ip);
            tracked_ips[i].disconnect_reported = 3;
        }
        else if (tracked_ips[i].disconnect_reported == 0) {
            // 未报告过断开，按超时处理
            printf("[SOCKS5] %s 超时断开连接 (程序退出)\n", tracked_ips[i].ip);
            tracked_ips[i].disconnect_reported = 2;
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
    DeleteCriticalSection(&g_tracker_lock);
}

void conn_tracker_stop(void)
{
#ifdef _WIN32
    tracker_running = 0;
    if (timeout_thread_handle) {
        WaitForSingleObject(timeout_thread_handle, 2000);
        CloseHandle(timeout_thread_handle);
        timeout_thread_handle = NULL;
    }
#endif
}

int conn_track_connect(const char* client_ip)
{
    int result = 0;
    EnterCriticalSection(&g_tracker_lock);

    tracked_ip_t* tip = find_or_create_ip(client_ip);
    if (!tip) {
        LeaveCriticalSection(&g_tracker_lock);
        return 0; // 数组满，无法记录，返回 0
    }

    time_t now = time(NULL);

    if (tip->active_connections == 0) {
        tip->logged_connect = 0;
        tip->logged_disconnect = 0;
        tip->disconnect_reported = 0;  // 重置，允许再次报告
    }

    tip->active_connections++;
    tip->last_seen = now;

    if (!tip->logged_connect) {
        tip->logged_connect = 1;
        result = 1;  // 是新连接
    }

    LeaveCriticalSection(&g_tracker_lock);
    return result;
}

void conn_track_disconnect(const char* client_ip)
{
    EnterCriticalSection(&g_tracker_lock);

    time_t now = time(NULL);

    for (int i = 0; i < tracked_count; i++) {
        if (strcmp(tracked_ips[i].ip, client_ip) == 0) {
            if (tracked_ips[i].active_connections > 0) {
                tracked_ips[i].active_connections--;
                tracked_ips[i].last_seen = now;

                if (tracked_ips[i].active_connections == 0) {
                    if (tracked_ips[i].disconnect_reported == 0) {
                        printf("[SOCKS5] %s 客户端断开连接\n", tracked_ips[i].ip);
                        tracked_ips[i].disconnect_reported = 1;
                        tracked_ips[i].logged_disconnect = 1;
                    }
                }
            }
            break;
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
}

void conn_track_check_timeout(void)
{
    EnterCriticalSection(&g_tracker_lock);

    time_t now = time(NULL);

    for (int i = 0; i < tracked_count; i++) {
        if (tracked_ips[i].active_connections == 0 &&
            tracked_ips[i].disconnect_reported == 0) {
            if (now - tracked_ips[i].last_seen >= CONN_TIMEOUT_SEC) {
                printf("[SOCKS5] %s 超时断开连接\n", tracked_ips[i].ip);
                tracked_ips[i].disconnect_reported = 2;
                tracked_ips[i].logged_disconnect = 1;
            }
        }
    }

    LeaveCriticalSection(&g_tracker_lock);
}

#ifdef _WIN32
DWORD WINAPI timeout_checker_thread(LPVOID lpParam)
{
    while (tracker_running) {
        Sleep(1000);
        conn_track_check_timeout();
    }
    return 0;
}
#endif