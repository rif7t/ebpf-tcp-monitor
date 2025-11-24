/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCPCW_H
#define __TCPCW_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

// struct event {
// 	int pid;
// 	int ppid;
// 	unsigned exit_code;
// 	unsigned long long duration_ns;
// 	char comm[TASK_COMM_LEN];
// 	char filename[MAX_FILENAME_LEN];
// 	bool exit_event;
// };

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 skaddr;
	__u64 ts_microseconds;
	__u64 ts_delta;
	__u32 pid;
	__u16 family;
	__u16 sport;
	__u16 dport;
	int oldstate;
	int newstate;
	char task[TASK_COMM_LEN];
	unsigned long long interval_ns;
};



#endif /* __TCPCW_H */
