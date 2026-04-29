#include "dpi_async.h"
#include "tls_flow.h"
#include "http_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "ss_detect.h"

#define MAX_QUEUE_SIZE 4096
#define MAX_WORKERS 8

typedef struct {
    SOCKET client_sock;
    char client_ip[64];
    unsigned char data[8192];
    int len;
    int dir;
} dpi_task_t;

typedef struct {
    dpi_task_t tasks[MAX_QUEUE_SIZE];
    volatile int head;
    volatile int tail;
    HANDLE full_sem;
    HANDLE empty_sem;
    CRITICAL_SECTION lock;
} dpi_queue_t;

static dpi_queue_t g_queue;
static HANDLE g_workers[MAX_WORKERS];
static volatile int g_running = 0;
static int g_worker_count = 0;

static void queue_init(dpi_queue_t* q)
{
    q->head = 0;
    q->tail = 0;
    q->full_sem = CreateSemaphore(NULL, 0, MAX_QUEUE_SIZE, NULL);
    q->empty_sem = CreateSemaphore(NULL, MAX_QUEUE_SIZE, MAX_QUEUE_SIZE, NULL);
    InitializeCriticalSection(&q->lock);
}

static void queue_cleanup(dpi_queue_t* q)
{
    if (q->full_sem) CloseHandle(q->full_sem);
    if (q->empty_sem) CloseHandle(q->empty_sem);
    DeleteCriticalSection(&q->lock);
}

static int queue_push(dpi_queue_t* q, dpi_task_t* task)
{
    DWORD result = WaitForSingleObject(q->empty_sem, 0);
    if (result != WAIT_OBJECT_0) return 0;

    EnterCriticalSection(&q->lock);
    q->tasks[q->head] = *task;
    q->head = (q->head + 1) % MAX_QUEUE_SIZE;
    LeaveCriticalSection(&q->lock);

    ReleaseSemaphore(q->full_sem, 1, NULL);
    return 1;
}

static int queue_pop(dpi_queue_t* q, dpi_task_t* task)
{
    WaitForSingleObject(q->full_sem, INFINITE);
    if (!g_running) return 0;

    EnterCriticalSection(&q->lock);
    *task = q->tasks[q->tail];
    q->tail = (q->tail + 1) % MAX_QUEUE_SIZE;
    LeaveCriticalSection(&q->lock);

    ReleaseSemaphore(q->empty_sem, 1, NULL);
    return 1;
}

static DWORD WINAPI dpi_worker(LPVOID arg)
{
    dpi_task_t task;

    while (g_running) {
        if (queue_pop(&g_queue, &task)) {
            if (task.dir == 0) {
                // HTTP ¼ì²â
                parse_http((const char*)task.data, task.len, task.client_ip);

                // TLS SNI ¼ì²â
                tls_flow_push_with_ip((int)task.client_sock, task.data,
                    task.len, task.client_ip);

                // Shadowsocks ¼ì²â
                detect_shadowsocks(task.data, task.len, task.client_ip);
            }
        }
    }
    return 0;
}

void dpi_async_init(int worker_count)
{
    if (g_running) return;
    if (worker_count < 1) worker_count = 1;
    if (worker_count > MAX_WORKERS) worker_count = MAX_WORKERS;

    queue_init(&g_queue);
    g_running = 1;
    g_worker_count = worker_count;

    for (int i = 0; i < worker_count; i++) {
        g_workers[i] = CreateThread(NULL, 0, dpi_worker, NULL, 0, NULL);
    }

    printf("[DPI] Òì²½Ä£Ê½ÒÑ¿ªÆô, %d worker(s)\n", worker_count);
}

void dpi_async_stop(void)
{
    if (!g_running) return;
    g_running = 0;

    for (int i = 0; i < g_worker_count; i++) {
        ReleaseSemaphore(g_queue.full_sem, 1, NULL);
    }

    for (int i = 0; i < g_worker_count; i++) {
        if (g_workers[i]) {
            WaitForSingleObject(g_workers[i], 2000);
            CloseHandle(g_workers[i]);
            g_workers[i] = NULL;
        }
    }

    queue_cleanup(&g_queue);
    g_worker_count = 0;
}

void dpi_async_submit(SOCKET client_sock, const char* client_ip,
    const unsigned char* data, int len, int dir)
{
    if (!g_running || len <= 0 || len > 8192) return;

    dpi_task_t task;
    task.client_sock = client_sock;
    task.len = len;
    task.dir = dir;
    strcpy_s(task.client_ip, sizeof(task.client_ip), client_ip);
    memcpy(task.data, data, len);

    queue_push(&g_queue, &task);
}