#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdio.h>
#include "get-stacktrace.h"
#include <stdint.h>
#include <linux/sched.h>
#include <string.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
} perfmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(char *));
	__uint(value_size, sizeof(_Bool));
} program_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stack_trace_t);
} stackdata_map SEC(".maps");

/* Allocate per-cpu space twice the needed. For the code below
 *   usize = bpf_get_stack(ctx, raw_data, max_len, BPF_F_USER_STACK);
 *   if (usize < 0)
 *     return 0;
 *   ksize = bpf_get_stack(ctx, raw_data + usize, max_len - usize, 0);
 *
 * If we have value_size = MAX_STACK_RAWTP * sizeof(__u64),
 * verifier will complain that access "raw_data + usize"
 * with size "max_len - usize" may be out of bound.
 * The maximum "raw_data + usize" is "raw_data + max_len"
 * and the maximum "max_len - usize" is "max_len", verifier
 * concludes that the maximum buffer access range is
 * "raw_data[0...max_len * 2 - 1]" and hence reject the program.
 *
 * Doubling the to-be-used max buffer size can fix this verifier
 * issue and avoid complicated C programming massaging.
 * This is an acceptable workaround since there is one entry here.
 */
// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, __u32);
// 	__type(value, __u64[2 * MAX_STACK_RAWTP]);
// } rawdata_map SEC(".maps");

struct raw_syscalls_enter {
	unsigned short 	common_type;
	unsigned char 	common_flag;
	unsigned char   common_preempt_count;
	int common_pid; // can't actually use it

	long id;
	unsigned long args[6];	
};

struct syscalls_enter_excve {
	unsigned short 	common_type;
	unsigned char 	common_flag;
	unsigned char   common_preempt_count;
	int common_pid; // can't actually use it

	int syscall_nr;
	const char *filename;
	const char *const * argv;
	const char *const * envp;	
};

SEC("tp/raw_syscalls/sys_enter")
int get_stacktrace(struct raw_syscalls_enter *ctx)
{
 	int max_len, max_buildid_len, total_size;
 	struct stack_trace_t *data;
 	long usize, ksize;
 	void *raw_data;
 	__u32 key = 0;
 	__u32 pid;
 	__u32 tgid;
 	__u64 pid_tgid;		
	const char* target_program = "bomb";
	char program_name[100];
	

 	data = bpf_map_lookup_elem(&stackdata_map, &key);
 	if (!data) {
 		return 0;
 	}
 	

	if (bpf_get_current_comm(&program_name, sizeof(program_name)) < 0) {
		bpf_printk("Error while getting process name");
		return 0;
	}

	if (!bpf_map_lookup_elem(&program_map, &program_name)) {
		// skip process if not present in the map
		return 0;
	}
	
	
  	pid_tgid = bpf_get_current_pid_tgid();
  	pid = pid_tgid >> 32; 
  	tgid = pid_tgid & 0xffff;
		
	bpf_printk("[+] Program: %s", program_name);
	bpf_printk("	PID: %llu", pid);
	bpf_printk("	TGID: %llu", tgid);
 	bpf_printk("	[syscall: %ld] (%lx, %s, %lx, %lx, %lx, %lx)", ctx->id, ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3], ctx->args[4], ctx->args[5]);
 
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
