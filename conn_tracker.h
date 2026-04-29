#pragma once
#ifndef CONN_TRACKER_H
#define CONN_TRACKER_H

#ifdef __cplusplus
extern "C" {
#endif

	void conn_tracker_init(void);
	void conn_tracker_cleanup(void);
	void conn_tracker_stop(void);  //停止超时检查线程

	// 记录连接建立，返回 1 表示是新连接，0 表示已知连接
	int conn_track_connect(const char* client_ip);

	// 记录连接断开
	void conn_track_disconnect(const char* client_ip);

	// 定期检查超时（需要在独立线程中调用）
	void conn_track_check_timeout(void);

#ifdef _WIN32
#include <windows.h>
	// Windows 下的超时检查线程函数
	DWORD WINAPI timeout_checker_thread(LPVOID lpParam);
#endif

#ifdef __cplusplus
}
#endif

#endif