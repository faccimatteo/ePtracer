/* vmlinux.h must be the first one to be included if using BTF */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <string.h>

#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"

// Detect Android
#if defined(__ANDROID__) || defined(ANDROID_SMP) || defined(CONFIG_ANDROID) || defined(__aarch64__) || defined(__arm__)
    #define IS_ANDROID 1
#else
    #define IS_ANDROID 0
#endif

// Hardcoded ioctl commands for binder on Android to avoid missing header issues (e.g., in eadb Debian chroot)
#ifndef BINDER_WRITE_READ
    #define BINDER_WRITE_READ       0xc0306201
#endif
#ifndef BINDER_SET_CONTEXT_MGR
    #define BINDER_SET_CONTEXT_MGR  0x40046207
#endif

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
    __type(value, char[MAX_PROGRAM_STRING_LEN]); 
} program_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stack_trace_t);
} stackdata_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct raw_syscall_t);
} syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_rb_map SEC(".maps");


/* Workaround as bpf_strncmp not working*/
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

/* Checks if event's process name is the one we want to trace */
static __always_inline __u32 is_target_program()
{
    const char *program_to_trace = NULL;
    __u32 key = 0, pid = 0;
    __u64 pid_tgid = 0, pid_to_trace = 0;
    char program_name[MAX_PROGRAM_STRING_LEN];

    if (bpf_get_current_comm(&program_name, MAX_PROGRAM_STRING_LEN) < 0)
    {
        bpf_printk("[!] Error while getting process name");
        return 0;
    }

    program_to_trace = bpf_map_lookup_elem(&program_map, &key);
    if (!program_to_trace)
    {
        bpf_printk("[!] Error while getting process to trace");
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    /* Skip process if not identified by process name nor PID */
    if (str_equals(program_name, program_to_trace, MAX_PROGRAM_STRING_LEN) != 0)
    {
        pid_to_trace = 0;
        /* Alternative for bpf_strtoul since it is not available in every Kernel version */
        for (int i = 0; i < MAX_PROGRAM_STRING_LEN; i++) {
            char c = program_to_trace[i];
            if (c >= '0' && c <= '9') {
                pid_to_trace = pid_to_trace * 10 + (c - '0');
            } else {
                break;
            }
        }
        
        if (pid_to_trace == 0 || pid_to_trace != pid)
            return 0;
        else
            return pid;
    }

    return pid;
}

/* Stack traces analysis using perf events */
SEC("perf_event")
int get_stacktrace(void *ctx)
{
    int max_len = 0, max_buildid_len = 0, total_size = 0;
    struct stack_trace_t *data = NULL;
    char program_name[MAX_PROGRAM_STRING_LEN];
    __u32 key = 0, pid = 0, tgid = 0, prog_cmp_res = 0, processed_char = 0;
    __u64 pid_tgid = 0, pid_to_trace = 0;

    data = bpf_map_lookup_elem(&stackdata_map, &key);
    if (!data)
        return 0;
     
    pid = is_target_program();
    if (!pid)
        return 0;
    
    max_len = MAX_STACK_RAWTP * sizeof(__u64);
    max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);
    data->pid = pid;
    data->kern_stack_size = bpf_get_stack(
				ctx, 
				data->kern_stack,
                max_len, 
				0);
    if (data->kern_stack_size < 0)
        bpf_printk("bpf_get_stack: failed to get kernel stack");

    data->user_stack_size = bpf_get_stack(
				ctx, 
				data->user_stack,
				max_len,
                BPF_F_USER_STACK);
    if (data->user_stack_size < 0)
        bpf_printk("bpf_get_stack: failed to get user stack");
    
    bpf_perf_event_output(ctx, &perfmap, 0, data, sizeof(*data));
 
    return 0;
}

/* Terminate ptrace-based debugger when a tentative to hook the target process is made */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int terminate_ptrace_based_debugger(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_PTRACE;
    ev->pid = (int)ctx->args[1];
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    bpf_ringbuf_submit(ev, 0);
    
    //Terminate debugger sending SIG_KILL
    bpf_send_signal(9);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int read_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_READ;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_EXECVE;
    ev->pid = pid;
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];

    long ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    ev->str1[MAX_BUF_SIZE] = 0;

    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int fork_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_FORK;
    ev->pid = pid;
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int clone_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_CLONE;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int mprotect_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_MPROTECT;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_decode(struct trace_event_raw_sys_enter *ctx)
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    long ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[1]);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    ev->str1[MAX_BUF_SIZE] = 0;

    ev->type = EVENT_OPENAT;
    ev->pid = pid;
    ev->args[0] = ctx->args[0]; // dfd
    ev->args[2] = ctx->args[2]; // flags
    ev->args[3] = ctx->args[3]; // mode

    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int open_decode(struct trace_event_raw_sys_enter *ctx)
{

    __u32 flags, pid, mode;
    char filename[MAX_BUF_SIZE + 1] = {0};
    flags = ctx->args[1];
    mode = ctx->args[2];

    // Read user buffer safely
    long ret = bpf_probe_read_user(filename, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_printk("open error reading buffer: %ld", ret);
        return 0;
    }
    
    // Ensure null termination (for string printing)
    filename[MAX_BUF_SIZE] = 0;
    bpf_printk("open(filename=\"%s\", flags=\"%lu\", mode=\"%lu\")", "", flags, mode);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int mmap_decode(struct trace_event_raw_sys_enter *ctx) {
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_MMAP;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    ev->args[4] = ctx->args[4];
    ev->args[5] = ctx->args[5];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_write")
int write_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_WRITE;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int chown_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    long ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    ev->str1[MAX_BUF_SIZE] = 0;

    ev->type = EVENT_CHOWN;
    ev->pid = pid;
    ev->args[1] = ctx->args[1]; // uid
    ev->args[2] = ctx->args[2]; // gid
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
    bpf_probe_read_user(ev->str2, MAX_BUF_SIZE, (void*)ctx->args[1]);
    bpf_probe_read_user(ev->str3, MAX_BUF_SIZE, (void*)ctx->args[2]);

    ev->str1[MAX_BUF_SIZE] = ev->str2[MAX_BUF_SIZE] = ev->str3[MAX_BUF_SIZE] = 0;

    ev->type = EVENT_MOUNT;
    ev->pid = pid;
    ev->args[3] = ctx->args[3]; // flags
    ev->args[4] = ctx->args[4]; // data

    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_decode(struct trace_event_raw_sys_enter *ctx)
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    long ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    ev->str1[MAX_BUF_SIZE] = 0;

    ev->type = EVENT_UMOUNT;
    ev->pid = pid;
    ev->args[1] = ctx->args[1];

    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_ioctl")
int binder_ioctl_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    int fd = (int)ctx->args[0];
    unsigned long cmd = (unsigned long)ctx->args[1];

    #if IS_ANDROID
        // Check if the ioctl is targeting /dev/binder (fd might be cached)
        if (cmd != BINDER_WRITE_READ && cmd != BINDER_SET_CONTEXT_MGR) 
            return 0;
    #endif

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_IOCTL;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_setuid")
int setuid_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_SETUID;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int setgid_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_SETGID;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int capset_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_CAPSET;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int prctl_decode(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_PRCTL;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    ev->args[4] = ctx->args[4];
    bpf_ringbuf_submit(ev, 0);
 
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int keyctl_decode(struct trace_event_raw_sys_enter *ctx)
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->type = EVENT_KEYCTL;
    ev->pid = pid;
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    ev->args[4] = ctx->args[4];
    bpf_ringbuf_submit(ev, 0);
    
    return 0;
}

/* System call monitoring 
SEC("tracepoint/raw_syscalls/sys_enter")
int profile(struct raw_syscalls_enter *ctx)
{
    int max_len = 0, max_buildid_len = 0, total_size = 0, i = 0;
    char program_name[MAX_PROGRAM_STRING_LEN];
    const char *program_to_trace;
    unsigned long pid_to_trace = 0;
    __u32 key = 0, pid = 0, tgid = 0, prog_cmp_res = 0, processed_char = 0;
    __u64 pid_tgid = 0;
	struct raw_syscall_t *syscall_data = NULL; 
    char buf[256];

    syscall_data = bpf_map_lookup_elem(&syscall_map, &key);
    if (!syscall_data)
        return 0;

    if (bpf_get_current_comm(&program_name, MAX_PROGRAM_STRING_LEN) < 0) {
        bpf_printk("[!] Error while getting process name");
        return 0;
    }

    program_to_trace = bpf_map_lookup_elem(&program_map, &key);
    if (!program_to_trace) 
    {
        bpf_printk("[!] Error while getting program to trace");
        return 0;
    }
    
    pid = is_target_program();
    if (!pid)
        return 0;

    tgid = pid_tgid & 0xffff;
    
    syscall_data->pid = pid;
    syscall_data->tgid = tgid;
    syscall_data->syscall_id = ctx->id;

    for (i = 0; i < 6; ++i) {
        syscall_data->args[i] = ctx->args[i];
    }
    
    // Is syscall being traced?
    bpf_printk("	PID: 		%lu", pid);
    bpf_printk("	TGID: 		%lu", tgid);
    bpf_printk("	syscall id: 	%ld", syscall_data->syscall_id);
    bpf_printk("	args: 		(%s, %s, %s, %s, %s, %s)",  ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3], ctx->args[4], ctx->args[5]);
    
    bpf_printk("	args: 		(%s, %d, %d, _, _, _)",  ctx->args[0], ctx->args[1], ctx->args[2]);
    

    if (bpf_ringbuf_output(&syscall_rb_map, syscall_data, sizeof(*syscall_data), 0) < 0)
    {
        bpf_printk("[!] Error while sending event to ring buffer");
        return 0;
    }
    return 1;
}
*/

char _license[] SEC("license") = "GPL";
