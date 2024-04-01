#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdio.h>
#include "get-stacktrace.h"
#include <stdint.h>
#include <linux/sched.h>
#include <string.h>
#include <stdlib.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
} perfmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PROGRAM_TO_TRACE);
	__type(key, __u32);
	__type(value, sizeof(MAX_PROGRAM_STRING_LEN)); 
} program_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stack_trace_t);
} stackdata_map SEC(".maps");

static __always_inline __u32 str_equals(const char *s1, const char *s2, __u32 size)
{
    int len = 0;
    unsigned char c1, c2;
    for (len = 0; len < size; len++) {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
     }
     return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int get_stacktrace(struct raw_syscalls_enter *ctx)
{
 	int max_len, max_buildid_len, total_size;
 	struct stack_trace_t *data;
 	long usize, ksize;
 	void *raw_data;
 	__u32 key = 0, pid, tgid, prog_cmp_res;
	__u64 pid_tgid;
	char program_name[MAX_PROGRAM_STRING_LEN];
	const char *program_to_trace;

 	data = bpf_map_lookup_elem(&stackdata_map, &key);
 	if (!data)
 		return 0;
 	
	if (bpf_get_current_comm(&program_name, MAX_PROGRAM_STRING_LEN) < 0) {
		bpf_printk("[!] Error while getting process name");
		return 0;
	}

	program_to_trace = bpf_map_lookup_elem(&program_map, &key);
	if (!program_to_trace) {
		bpf_printk("[!] Error while getting program to trace");
		return 0;
	}

  // skip process if not present in the map
	if (str_equals(program_name, program_to_trace, sizeof(program_to_trace)) != 0)
       		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
  	pid = pid_tgid >> 32; 
  	tgid = pid_tgid & 0xffff;
		
	bpf_printk("[+] Program: %s", program_name);
	bpf_printk("	PID: 		%llu", pid);
	bpf_printk("	TGID: 		%llu", tgid);
	bpf_printk("	syscall id: 	%ld", ctx->id);
 	bpf_printk("	args: 		(%lx, %s, %lx, %lx, %lx, %lx)",  ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3], ctx->args[4], ctx->args[5]);
	
 	max_len = MAX_STACK_RAWTP * sizeof(__u64);
 	max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);
 	data->pid = pid;
 	data->kern_stack_size = bpf_get_stack(ctx, data->kern_stack,
 					      max_len, 0);
 	data->user_stack_size = bpf_get_stack(ctx, data->user_stack, max_len,
 					    BPF_F_USER_STACK);
 	data->user_stack_buildid_size = bpf_get_stack(
 		ctx, data->user_stack_buildid, max_buildid_len,
 		BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
 	bpf_perf_event_output(ctx, &perfmap, 0, data, sizeof(*data));
 
 	/* write both kernel and user stacks to the same buffer */
 	// raw_data = bpf_map_lookup_elem(&rawdata_map, &key);
 	// if (!raw_data)
 	// 	return 0;
 
 	// usize = bpf_get_stack(ctx, raw_data, max_len, BPF_F_USER_STACK);
 	// if (usize < 0)
 	// 	return 0;
 
 	// ksize = bpf_get_stack(ctx, raw_data + usize, max_len - usize, 0);
 	// if (ksize < 0)
 	// 	return 0;
 
 	// total_size = usize + ksize;
 	// if (total_size > 0 && total_size <= max_len)
 	// 	bpf_perf_event_output(ctx, &perfmap, 0, raw_data, total_size);
 
 	return 0;
 }

char _license[] SEC("license") = "GPL";
