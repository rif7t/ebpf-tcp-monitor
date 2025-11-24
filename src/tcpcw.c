// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "tcpcw.h"
#include "tcpcw.skel.h"


static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	
	const struct event *e = data;

	char saddr_str[INET6_ADDRSTRLEN];
	char daddr_str[INET6_ADDRSTRLEN];

	if (e->family == AF_INET) {
		struct in_addr s4, d4;
		s4.s_addr = (__u32)e->saddr;
		d4.s_addr = (__u32)e->daddr;

		inet_ntop(AF_INET, &s4, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET, &d4, daddr_str, sizeof(daddr_str));
	} else if (e->family == AF_INET6) {
		struct in6_addr s6, d6;

		/* Convert 128-bit values into struct in6_addr */
		memcpy(&s6, &e->saddr, sizeof(s6));
		memcpy(&d6, &e->daddr, sizeof(d6));

		inet_ntop(AF_INET6, &s6, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET6, &d6, daddr_str, sizeof(daddr_str));
	} else {
		snprintf(saddr_str, sizeof(saddr_str), "unknown");
		snprintf(daddr_str, sizeof(daddr_str), "unknown");
	}

	printf("\n----- TCP_CLOSE_WAIT Duration -----\n");
	printf("PID: %u\n", e->pid);
	printf("Task: %s\n", e->task);

	printf("Socket ptr: 0x%llx\n", e->skaddr);

	printf("Family: %s\n", 
		e->family == AF_INET  ? "AF_INET" :
		e->family == AF_INET6 ? "AF_INET6" :
		                        "OTHER");

	printf("Src: %s:%u\n", saddr_str, e->sport);
	printf("Dst: %s:%u\n", daddr_str, e->dport);

	printf("Old state: %d  ->  New state: %d\n",
		e->oldstate, e->newstate);

	printf("Timestamp (ns): %llu\n", e->ts_microseconds);
	printf("Duration (ns): %llu\n", e->ts_delta);

	printf("---------------------------\n");

	return 0;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct tcpcw_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = tcpcw_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	// __u16 key = 0;
	// __u16 value = 80;
	// bpf_map__update_elem(&skel->maps.sports, &key, sizeof(key), value, sizeof(value), BPF_ANY);
	/* Load & verify BPF programs */
	err = tcpcw_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = tcpcw_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	tcpcw_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
