#include "ss_detect.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
/*Shadowsocks加密协议检测,思路来自GFWREPORT*/
/*配置部分*/
#define MIN_POPCOUNT_SS       3.4f    // 最低熵值
#define MAX_POPCOUNT_SS       4.6f    // 最高熵值
#define MAX_PRINTABLE_RATIO   35.0f   // 可打印字符最大比例
#define MIN_PACKET_SIZE       20      // 最小检测数据包大小

// 已知排除
static const unsigned char SSH_BANNER[] = "SSH-";
static const unsigned char RDP_BANNER[] = { 0x03, 0x00, 0x00 };
static const unsigned char MYSQL_BANNER[] = { 0x4a, 0x00, 0x00, 0x00, 0x0a };

// ===== 辅助函数 =====

// 计算字节中 1 比特的数量
static int popcount_byte(unsigned char b)
{
    int count = 0;
    while (b) {
        count += b & 1;
        b >>= 1;
    }
    return count;
}

// 计算数据的平均每字节 1 比特数
static float calc_avg_popcount(const unsigned char* data, int len)
{
    if (len <= 0) return 0;

    int total_bits = 0;
    for (int i = 0; i < len; i++) {
        total_bits += popcount_byte(data[i]);
    }
    return (float)total_bits / len;
}

// 检查字节是否是可打印 ASCII
static int is_printable_ascii(unsigned char b)
{
    return (b >= 0x20 && b <= 0x7E);
}

// 计算可打印字符比例
static float calc_printable_ratio(const unsigned char* data, int len)
{
    if (len <= 0) return 0;

    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if (is_printable_ascii(data[i])) printable_count++;
    }
    return (float)printable_count / len * 100.0f;
}

// 检查是否是已知协议
static int is_known_protocol(const unsigned char* data, int len)
{
    if (len < 5) return 0;

    // SSH
    if (len >= 4 && memcmp(data, SSH_BANNER, 4) == 0) return 1;

    // RDP
    if (len >= 3 && data[0] == 0x03 && data[1] == 0x00) return 1;

    // MySQL
    if (len >= 5 && memcmp(data, MYSQL_BANNER, 5) == 0) return 1;

    // TDS (SQL Server)
    if (len >= 8 && data[0] == 0x12 && data[1] == 0x01) return 1;

    // PostgreSQL
    if (len >= 8 && data[0] == 0x00 && data[4] == 0x00) return 1;

    return 0;
}

// 检查字节分布是否均匀
static int is_uniform_distribution(const unsigned char* data, int len)
{
    if (len < 20) return 0;

    int byte_count[256] = { 0 };
    for (int i = 0; i < len; i++) {
        byte_count[data[i]]++;
    }

    // 计算出现过的不同字节数
    int unique_bytes = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_count[i] > 0) unique_bytes++;
    }

    // 加密数据应该有多样化的字节
    float diversity = (float)unique_bytes / (float)len;
    return (unique_bytes >= 15 && diversity > 0.3f);
}

// 检查是否有明显的协议结构
static int has_protocol_structure(const unsigned char* data, int len)
{
    if (len < 4) return 0;

    // 检查是否有重复的模式
    // 例如：前4字节中有3个相同
    int same_count = 0;
    for (int i = 1; i < 4; i++) {
        if (data[i] == data[0]) same_count++;
    }
    if (same_count >= 2) return 1;  // 高度重复，可能是协议头

    // 检查是否有递增序列
    if (data[1] == data[0] + 1 && data[2] == data[1] + 1) return 1;

    return 0;
}

// ===== GFW 豁免规则=====

static int check_ex2_prefix_printable(const unsigned char* data, int len)
{
    if (len < 6) return 0;
    for (int i = 0; i < 6; i++) {
        if (!is_printable_ascii(data[i])) return 0;
    }
    return 1;
}

static int check_ex3_half_printable(const unsigned char* data, int len)
{
    return (calc_printable_ratio(data, len) > 50.0f);
}

static int check_ex4_consecutive_printable(const unsigned char* data, int len)
{
    int max_consecutive = 0;
    int current = 0;

    for (int i = 0; i < len; i++) {
        if (is_printable_ascii(data[i])) {
            current++;
            if (current > max_consecutive) max_consecutive = current;
        }
        else {
            current = 0;
        }
    }
    return (max_consecutive > 20);
}

static int check_ex5_tls(const unsigned char* data, int len)
{
    if (len < 3) return 0;

    // 检查 TLS Record 类型
    // 0x14 = ChangeCipherSpec
    // 0x15 = Alert
    // 0x16 = Handshake (ClientHello/ServerHello等)
    // 0x17 = Application Data
    unsigned char record_type = data[0];

    // TLS Record 类型必须是 0x14-0x17
    if (record_type < 0x14 || record_type > 0x17) {
        return 0;
    }

    // 检查 TLS 版本: 0x03 [0x00-0x04]
    // TLS 1.0 = 0x0301
    // TLS 1.1 = 0x0302
    // TLS 1.2 = 0x0303
    // TLS 1.3 = 0x0304
    if (data[1] == 0x03 && data[2] >= 0x00 && data[2] <= 0x04) {
        return 1;
    }

    return 0;
}

static int check_ex5_http(const unsigned char* data, int len)
{
    if (len < 4) return 0;

    const char* methods[] = { "GET ", "PUT ", "POST ", "HEAD " };
    for (int i = 0; i < 4; i++) {
        if (len >= 4 && memcmp(data, methods[i], 4) == 0) return 1;
    }

    char buf[5] = { 0 };
    for (int i = 0; i < 4; i++) buf[i] = tolower(data[i]);
    if (strcmp(buf, "get ") == 0 || strcmp(buf, "put ") == 0 ||
        strcmp(buf, "post") == 0 || strcmp(buf, "head") == 0) {
        if (buf[3] == ' ' || (len > 4 && data[4] == ' ')) return 1;
    }
    return 0;
}

// ===== 增强版 SS 检测 =====

static int is_likely_encrypted_tunnel(const unsigned char* data, int len)
{
    if (len < MIN_PACKET_SIZE) return 0;

    float avg_pop = calc_avg_popcount(data, len);
    float printable_ratio = calc_printable_ratio(data, len);

    // 条件1：熵值必须在严格加密范围内
    int cond_entropy = (avg_pop >= MIN_POPCOUNT_SS && avg_pop <= MAX_POPCOUNT_SS);

    // 条件2：可打印字符比例必须很低
    int cond_printable = (printable_ratio <= MAX_PRINTABLE_RATIO);

    // 条件3：字节分布必须均匀
    int cond_uniform = is_uniform_distribution(data, len);

    // 条件4：首字节不能是0
    int cond_first_byte = (data[0] != 0x00);

    // 条件5：不能有明显的协议结构
    int cond_no_structure = !has_protocol_structure(data, len);

    // 条件6：不能是已知协议
    int cond_not_known = !is_known_protocol(data, len);

    // 条件7：不符合豁免规则
    int cond_not_exempt = !(check_ex2_prefix_printable(data, len) ||
        check_ex3_half_printable(data, len) ||
        check_ex4_consecutive_printable(data, len) ||
        check_ex5_tls(data, len) ||
        check_ex5_http(data, len));

    // 所有条件必须同时满足
    return (cond_entropy &&
        cond_printable &&
        cond_uniform &&
        cond_first_byte &&
        cond_no_structure &&
        cond_not_known &&
        cond_not_exempt);
}

// ===== 主检测函数 =====

int detect_shadowsocks(const unsigned char* data, int len, const char* client_ip)
{
    if (len < MIN_PACKET_SIZE) return 0;

    // 先快速排除明显的已知协议
    if (check_ex5_tls(data, len) || check_ex5_http(data, len)) {
        return 0;  // TLS/HTTP 正常流量
    }

    if (is_known_protocol(data, len)) {
        return 0;  // SSH/RDP/MySQL等正常协议
    }

    // 深度检测
    if (is_likely_encrypted_tunnel(data, len)) {
        float avg_pop = calc_avg_popcount(data, len);
        float printable_ratio = calc_printable_ratio(data, len);

        printf("[加密隧道检测] %s -> 疑似加密隧道 ", client_ip);
        printf("(流量平均熵值=%.2f, 可打印ASCII比例=%.1f%%)\n", avg_pop, printable_ratio);

        // 输出前16字节用于分析
        printf("[异常数据流] ");
        for (int i = 0; i < (len < 16 ? len : 16); i++) {
            printf("%02x ", data[i]);
        }
        printf("\n");

        return 1;
    }

    return 0;
}