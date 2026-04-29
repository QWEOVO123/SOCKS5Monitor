#pragma once
#ifndef NET_H
#define NET_H

#include <winsock2.h>

int net_init();
SOCKET net_tcp_connect(const char* host, int port);
void net_close(SOCKET s);

#endif