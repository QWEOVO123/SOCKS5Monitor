#pragma once
#ifndef TLS_PARSER_H
#define TLS_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

	void parse_tls_sni(const unsigned char* data, int len);

#ifdef __cplusplus
}
#endif

#endif /* TLS_PARSER_H */