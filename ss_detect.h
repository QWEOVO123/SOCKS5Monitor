#pragma once
#ifndef SS_DETECT_H
#define SS_DETECT_H

#ifdef __cplusplus
extern "C" {
#endif

	// 检测 Shadowsocks/代理协议
	// 返回值：1=检测到疑似代理流量，0=正常流量
	int detect_shadowsocks(const unsigned char* data, int len, const char* client_ip);

#ifdef __cplusplus
}
#endif

#endif