#include <stdio.h>
#include "dpi.h"
#include "http_parser.h"
#include "tls_parser.h"
#include "tls_flow.h"
#include "ss_detect.h"

static void dpi_sync_inspect(
    SOCKET client_sock,
    const char* client_ip,
    const char* data,
    int len,
    int dir)
{
    /* HTTP 检测 */
    parse_http(data, len, client_ip);

    /* TLS SNI 检测 - 只检测客户端发出的数据 */
    if (dir == 0) {
        tls_flow_push_with_ip((int)client_sock, (const unsigned char*)data, len, client_ip);
    }

    /* Shadowsocks 检测 - 只检测客户端发出的第一个数据包 */
    if (dir == 0) {
        detect_shadowsocks((const unsigned char*)data, len, client_ip);
    }
}

void dpi_sync_init(void)
{
    tls_flow_init();
    dpi_set_hook(dpi_sync_inspect);
}