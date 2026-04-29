// tls_flow.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tls_flow.h"  // 必须包含头文件

#define FLOW_BUF_SIZE 8192
#define MAX_FLOWS 1024

typedef struct
{
    unsigned char buf[FLOW_BUF_SIZE];
    int len;
    int sni_parsed;
    char client_ip[64];
} tls_flow_t;

static tls_flow_t flows[MAX_FLOWS];

void tls_flow_init()
{
    memset(flows, 0, sizeof(flows));
}

void tls_flow_cleanup(int flow_id)
{
    if (flow_id >= 0 && flow_id < MAX_FLOWS) {
        memset(&flows[flow_id], 0, sizeof(tls_flow_t));
    }
}

// 前置声明
static void parse_tls_sni_internal(tls_flow_t* f);
static int parse_client_hello(const unsigned char* data, int len, char* out_host, int out_host_size);

// 旧接口
void tls_flow_push(int flow_id, const unsigned char* data, int len)
{
    tls_flow_push_with_ip(flow_id, data, len, "unknown");
}

// 新接口
void tls_flow_push_with_ip(int flow_id, const unsigned char* data, int len, const char* client_ip)
{
    if (!data || len <= 0) return;
    if (flow_id < 0 || flow_id >= MAX_FLOWS) return;

    tls_flow_t* f = &flows[flow_id];

    // 保存客户端 IP（首次设置）
    if (f->client_ip[0] == '\0' && client_ip) {
        strcpy_s(f->client_ip, sizeof(f->client_ip), client_ip);
    }

    // 已经解析过 SNI，直接丢弃数据
    if (f->sni_parsed) {
        return;
    }

    // 防止单包过大
    if (len > FLOW_BUF_SIZE) {
        f->len = 0;
        return;
    }

    // 防止溢出
    if (f->len + len > FLOW_BUF_SIZE) {
        f->len = 0;
    }

    // 累积数据
    memcpy(f->buf + f->len, data, len);
    f->len += len;

    // 尝试解析
    parse_tls_sni_internal(f);
}

// 返回值：1=成功解析，0=未找到，-1=数据不完整
static int parse_client_hello(const unsigned char* data, int len, char* out_host, int out_host_size)
{
    //Handshake 头部
    if (len < 4) return -1;

    if (data[0] != 0x01) return 0;

    int hs_len = (data[1] << 16) | (data[2] << 8) | data[3];
    if (len - 4 < hs_len) return -1;

    int pos = 4;

    // 2. 跳过 ClientHello 固定头部
    if (pos + 34 > len) return -1;
    pos += 2;
    pos += 32;

    if (pos >= len) return -1;
    int sid_len = data[pos];
    pos += 1 + sid_len;
    if (pos > len) return -1;

    if (pos + 2 > len) return -1;
    int cs_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cs_len;
    if (pos > len) return -1;

    if (pos >= len) return -1;
    int comp_len = data[pos];
    pos += 1 + comp_len;
    if (pos > len) return -1;

    if (pos + 2 > len) return 0;
    int ext_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    int end = pos + ext_len;
    if (end > len) end = len;

    //遍历扩展
    while (pos + 4 <= end) {
        int type = (data[pos] << 8) | data[pos + 1];
        int ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (ext_data_len < 0 || pos + ext_data_len > end) {
            break;
        }

        if (type == 0x0000) {
            if (pos + 2 > end) return -1;
            int list_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;

            int list_end = pos + list_len;
            if (list_end > end) list_end = end;

            if (pos + 3 <= list_end) {
                int sni_type = data[pos];
                int sni_len = (data[pos + 1] << 8) | data[pos + 2];
                pos += 3;

                if (sni_type == 0x00 && sni_len > 0 && pos + sni_len <= list_end) {
                    if (out_host && out_host_size > 0) {
                        int copy_len = sni_len < (out_host_size - 1) ? sni_len : (out_host_size - 1);
                        memcpy(out_host, data + pos, copy_len);
                        out_host[copy_len] = '\0';
                    }
                    return 1;
                }
            }
            return 0;
        }

        pos += ext_data_len;
    }

    return 0;
}

static void parse_tls_sni_internal(tls_flow_t* f)
{
    const unsigned char* data = f->buf;
    int len = f->len;
    int offset = 0;

    while (offset + 5 <= len) {
        if (data[offset] != 0x16) {
            offset++;
            continue;
        }

        int tls_version = (data[offset + 1] << 8) | data[offset + 2];
        if (tls_version < 0x0301) {
            offset++;
            continue;
        }

        int record_len = (data[offset + 3] << 8) | data[offset + 4];

        if (record_len <= 0 || record_len > 16384) {
            offset++;
            continue;
        }

        if (offset + 5 + record_len > len) {
            return;
        }

        const unsigned char* rec = data + offset + 5;

        if (rec[0] == 0x01) {
            char host[256] = { 0 };
            int result = parse_client_hello(rec, record_len, host, sizeof(host));

            if (result == 1) {
                printf("[SNI检测] %s -> %s\n", f->client_ip, host);
                f->sni_parsed = 1;
                f->len = 0;
                return;
            }
            else if (result == 0) {
                f->sni_parsed = 1;
                f->len = 0;
                return;
            }
        }

        offset += 5 + record_len;
    }
}