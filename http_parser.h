#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

void parse_http(const char* data, int len, const char* client_ip);

#endif