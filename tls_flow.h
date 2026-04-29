// tls_flow.h
#pragma once
#ifndef TLS_FLOW_H
#define TLS_FLOW_H

#ifdef __cplusplus
extern "C" {
#endif

	void tls_flow_init(void);
	void tls_flow_push(int flow_id, const unsigned char* data, int len);
	void tls_flow_push_with_ip(int flow_id, const unsigned char* data, int len, const char* client_ip);
	void tls_flow_cleanup(int flow_id);

#ifdef __cplusplus
}
#endif

#endif