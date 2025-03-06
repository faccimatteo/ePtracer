// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>
#include "common.h"
#include "jdwp.skel.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct tcp_data_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("Received %ld bytes: %s", strlen(e->data), e->data);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct jdwp_bpf *skel;
    int prog_fd, ifindex, err;
    char ifname[IF_NAMESIZE];

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    strncpy(ifname, argv[1], IF_NAMESIZE);
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
        return 1;
    } 

	/* Load and verify BPF application */
	skel = jdwp_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skel\n");
		return 1;
	}

    bpf_program__set_type(skel->progs.filter_jdwp_packets, BPF_PROG_TYPE_XDP);
    // Get the program FD
    prog_fd = bpf_program__fd(skel->progs.filter_jdwp_packets);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find XDP program: %s\n", strerror(-prog_fd));
        return 1;
    }

	/* Set up ring buffer polling 
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.filter_jdwp_packets, ifindex);
	if (!link) {
		printf("attach error\n");
		return 1;
	}

	printf("Attach XDP success\n");

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}
    
cleanup:
	ring_buffer__free(rb);
	jdwp_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
