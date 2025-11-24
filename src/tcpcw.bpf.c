// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpcw.h"

#define MAX_ENTRIES 10240
#define AF_INET 2
#define AF_INET6 10

const volatile bool filter_by_sport = false;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 10240);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u16);
	__type(value, u16);

} sports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u16);
	__type(value, u16);

} dports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, u64);
} timestamps SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sock/inet_sock_set_state")
int handle_tcpstate_change(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if(ctx->newstate == TCP_CLOSE_WAIT || ctx->oldstate == TCP_CLOSE_WAIT){
		struct sock *sk = (struct sock *)ctx->skaddr;

		struct task_struct *task;
		__u16 family = ctx->family;
		__u16 sport = ctx->sport;
		__u16 dport = ctx->dport;
		__u64 *tsp, delta_ns, ts;

		if(ctx->protocol != IPPROTO_TCP)
		return 0;

		if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
		return 0;

		__u32 key = 0;
		struct event *cw_intvl;

		tsp = bpf_map_lookup_elem(&timestamps, &sk);
		ts = bpf_ktime_get_ns();

		if(!tsp)
					delta_ns = 0;
				else
					delta_ns = (ts - *tsp);
		
		cw_intvl = bpf_ringbuf_reserve(&rb, sizeof(*cw_intvl), 0);
		if (!cw_intvl)
			return 0;

		cw_intvl->dport = dport;
		cw_intvl->sport = sport;
		cw_intvl->family = family;
		cw_intvl->oldstate = ctx->oldstate;
		cw_intvl->newstate = ctx->newstate;
		cw_intvl->pid = bpf_get_current_pid_tgid();
		cw_intvl->ts_microseconds =  ts;
		cw_intvl->skaddr = (__u64)sk;
		cw_intvl->ts_delta = delta_ns;
		bpf_get_current_comm(cw_intvl->task, sizeof(cw_intvl->task));

		
		
		if(family == AF_INET){
			bpf_probe_read_kernel(&cw_intvl->saddr, sizeof(cw_intvl->saddr), &sk->__sk_common.skc_rcv_saddr);
			bpf_probe_read_kernel(&cw_intvl->daddr, sizeof(cw_intvl->daddr), &sk->__sk_common.skc_daddr);
		}
		else{
			bpf_probe_read_kernel(&cw_intvl->saddr, sizeof(cw_intvl->skaddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
			bpf_probe_read_kernel(&cw_intvl->saddr, sizeof(cw_intvl->saddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

		}
		
		
		if (ctx->newstate == TCP_CLOSE_WAIT){
			bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);
			
		}
		else if(ctx->oldstate == TCP_CLOSE_WAIT){	
			bpf_map_delete_elem(&timestamps, &sk);
		}	
		if(ctx->oldstate == TCP_CLOSE_WAIT)
			bpf_ringbuf_submit(cw_intvl, 0);
		else
			bpf_ringbuf_discard(cw_intvl, 0);
	
	}
	return 0;
}
