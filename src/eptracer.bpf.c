#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <linux/sched.h>
#include <string.h>
#include <stdlib.h>

#include "lib/stack_tracing.h"
#include "lib/syscall_tracing.h"
		
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} syscall_map SEC(".maps");


static __always_inline __u32 str_equals(const char *s1, const char *s2, __u32 size)
{
    int len = 0;
    unsigned char c1, c2;
    for (len = 0; len < size; ++len) {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
    }
    return 0;
}

/* Stack traces analysis using perf events */
SEC("perf_event")
int get_stacktrace(void *ctx)
{
    int max_len = 0, max_buildid_len = 0, total_size = 0;
    struct stack_trace_t *data = NULL;
    char program_name[MAX_PROGRAM_STRING_LEN];
	const char *program_to_trace= NULL;
    unsigned long pid_to_trace = 0;
    __u32 key = 0, pid = 0, tgid = 0, prog_cmp_res = 0, processed_char = 0;
    __u64 pid_tgid = 0;
 

    data = bpf_map_lookup_elem(&stackdata_map, &key);
    if (!data)
      return 0;
 	
    if (bpf_get_current_comm(&program_name, MAX_PROGRAM_STRING_LEN) < 0) {
        bpf_printk("[!] Error while getting process name");
        return 0;
    }

    program_to_trace = bpf_map_lookup_elem(&program_map, &key);
    if (!program_to_trace) {
        bpf_printk("[!] Error while getting program to tlinking all the necessary librariesrace");
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
  	 pid = pid_tgid >> 32; 
	
    // skip process if not identified by process name nor PID 
    if (str_equals(program_name, program_to_trace, sizeof(program_to_trace)) != 0) {
        processed_char = bpf_strtoul(program_to_trace, sizeof(program_to_trace), 10, &pid_to_trace);
        if (processed_char == EINVAL) {
            bpf_printk("bpf_strtoul: no valid digits were found or unsupported base was provided"); 
        }
        if (processed_char == ERANGE) {
            bpf_printk("bpf_strtoul: resulting value was out of range");  
        }
        if (pid_to_trace != pid)
            return 0;
    }

    max_len = MAX_STACK_RAWTP * sizeof(__u64);
    max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);
    data->pid = pid;
    data->kern_stack_size = bpf_get_stack(
				ctx, 
				data->kern_stack,
                max_len, 
				0);
    if (data->kern_stack_size < 0) {
      bpf_printk("bpf_get_stack: failed to get kernel stack");
    }
    data->user_stack_size = bpf_get_stack(
				ctx, 
				data->user_stack,
				max_len,
                BPF_F_USER_STACK);
    if (data->user_stack_size < 0) {
      bpf_printk("bpf_get_stack: failed to get user stack");
    }
    
    bpf_perf_event_output(ctx, &perfmap, 0, data, sizeof(*data));
 
    return 0;
}

/* System call monitoring */
// SEC("tracepoint/raw_syscalls/sys_enter")
// int profile(struct raw_syscalls_enter *ctx)
// {
// 		int max_len = 0, max_buildid_len = 0, total_size = 0, i = 0;
// 		char program_name[MAX_PROGRAM_STRING_LEN];
// 		const char *program_to_trace;
// 		unsigned long pid_to_trace = 0;
// 		__u32 key = 0, pid = 0, tgid = 0, prog_cmp_res = 0, processed_char = 0;
// 		__u64 pid_tgid = 0;
// 		struct raw_syscall_t *syscall_data = NULL; 
// 
//     if (bpf_get_current_comm(&program_name, MAX_PROGRAM_STRING_LEN) < 0) {
//         bpf_printk("[!] Error while getting process name");
//         return 0;
//     }
// 
//     program_to_trace = bpf_map_lookup_elem(&program_map, &key);
//     if (!program_to_trace) {
//         bpf_printk("[!] Error while getting program to trace");
//         return 0;
//     }
// 
//     pid_tgid = bpf_get_current_pid_tgid();
//   	pid = pid_tgid >> 32; 
// 
//     // skip process if not identified by process name nor PID 
//     if (str_equals(program_name, program_to_trace, sizeof(program_to_trace)) != 0) {
//         processed_char = bpf_strtoul(program_to_trace, sizeof(program_to_trace), 10, &pid_to_trace);
//         if (processed_char == EINVAL) {
//             bpf_printk("bpf_strtoul: no valid digits were found or unsupported base was provided"); 
//         }
//         if (processed_char == ERANGE) {
//             bpf_printk("bpf_strtoul: resulting value was out of range");  
//         }
//         if (pid_to_trace != pid)
//             return 0;
//     }
// 
//     tgid = pid_tgid & 0xffff;
//     
//     //syscall_dat->program_name = program_name;
//     syscall_data->pid = pid;
//     syscall_data->tgid = tgid;
//     syscall_data->syscall_id = ctx->id;
// 
//     for (i = 0; i < 6; ++i) {
//       syscall_data->args[i] = ctx->args[i];
//     }
//     
//     // bpf_printk("[+] Program: %s", program_name);
//     // bpf_printk("	PID: 		%lu", pid);
//     // bpf_printk("	TGID: 		%lu", tgid);
//     // bpf_printk("	syscall id: 	%ld", ctx->id);
//     // bpf_printk("	args: 		(%lx, %s, %lx, %lx, %lx, %lx)",  ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3], ctx->args[4], ctx->args[5]);
// 
//     if (bpf_ringbuf_output(&syscall_map, syscall_data, sizeof(syscall_data), 0) < 0) {
//         bpf_printk("[!] Error while sending event to ring buffer");
//         return 0;
//     }
//   return 1;
// }


char _license[] SEC("license") = "GPL";
