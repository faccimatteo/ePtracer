/* vmlinux.h must be the first one to be included if using BTF */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <string.h>

#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"

// Detect Android
#if defined(__ANDROID__) || defined(ANDROID_SMP) || defined(CONFIG_ANDROID)
    #define IS_ANDROID 1
    #include <linux/android/binder.h>  // Android-specific headers
#else
    #define IS_ANDROID 0
    // Fallback definitions for non-Android
    #define BINDER_WRITE_READ  _IOWR('b', 1, struct binder_write_read)
    #define BINDER_SET_CONTEXT_MGR  _IOW('b', 7, int)
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

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"ptrace\", request=\"%d\", pid=\"%d\", addr=\"%p\", data=\"%p\"} ", (int)ctx->args[1], 
                (int)ctx->args[0], (int)ctx->args[1], (void*)ctx->args[2], (void*)ctx->args[3]);
    bpf_ringbuf_submit(str_out, 0);
    
    //Terminate debugger sending SIG_KILL
    bpf_send_signal(9);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int read_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"read\", fd=\"%d\", buf=\"%p\", count=\"%lu\"} ", pid,
                (int)ctx->args[0], (void*)ctx->args[1], (unsigned long)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    const int size = 150;
    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, size, 0);
    if (!str_out) return 0;

    char filename[MAX_BUF_SIZE + 1] = {0};
    long ret = bpf_probe_read_user(filename, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_ringbuf_discard(str_out, 0);
        return 0;
    }
    filename[MAX_BUF_SIZE] = 0;

    BPF_SNPRINTF(str_out, size, "eptracer{pid=\"%d\", syscall=\"execve\", filename=\"%s\", argv=\"%p\", envp=\"%p\"}", pid,
                filename, (void*)ctx->args[1], (void*)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int fork_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 50, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 50, "eptracer{pid=\"%d\", syscall=\"fork\"} ", pid);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int clone_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"clone\", flags=\"%lx\", child_stack=\"%p\", parent_tid=\"%p\", child_tid=\"%p\"} ", pid,
                ctx->args[0], (void*)ctx->args[1], (void*)ctx->args[2], (void*)ctx->args[3]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int mprotect_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"mprotect\", addr=\"%p\", len=\"%lu\", prot=\"%d\"} ", pid, 
                (void*)ctx->args[0], (unsigned long)ctx->args[1], (int)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_decode(struct trace_event_raw_sys_enter *ctx)
{
    int dfd, flags, mode, pid;
    char filename[MAX_BUF_SIZE + 1] = {0};
    __u32 key = 0, tgid = 0;
    struct raw_syscall_t *syscall_data = NULL;
    char *str_out = NULL; // Initialize to NULL

    pid = is_target_program();
    if (!pid)
        return 0;

    const int size = 100;
    str_out = bpf_ringbuf_reserve(&syscall_rb_map, size, 0);
    if (!str_out)
        return 0;

    long ret = bpf_probe_read_user(filename, MAX_BUF_SIZE, (void*)ctx->args[1]);
    if (ret < 0) {
        bpf_printk("openat error reading buffer: %ld", ret);
        bpf_ringbuf_discard(str_out, 0); // Release on error
        return 0;
    }
    
    filename[MAX_BUF_SIZE] = 0;
 
    dfd = ctx->args[0];
    flags = ctx->args[2];
    mode = ctx->args[3];

    BPF_SNPRINTF(str_out, size, "eptracer{pid=\"%d\", syscall=\"openat\", fd=\"%d\", filename=\"%s\", flags=\"%d\", mode=\"%d\"} ", pid,
                dfd, filename, flags, mode);
    bpf_ringbuf_submit(str_out, 0);
    
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

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 150, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 150, "eptracer{pid=\"%d\", syscall=\"mmap\", addr=\"%p\", length=\"%lu\", prot=\"%d\", flags=\"%d\", fd=\"%d\", off=\"%lu\"} ", pid,
                (void*)ctx->args[0], (unsigned long)ctx->args[1], (int)ctx->args[2],
                (int)ctx->args[3], (int)ctx->args[4], (unsigned long)ctx->args[5]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_write")
int write_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"write\", fd=\"%d\", buf=\"%p\", count=\"%lu\"} ", pid,
                (int)ctx->args[0], (void*)ctx->args[1], (unsigned long)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int chown_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char filename[MAX_BUF_SIZE + 1] = {0};
    long ret = bpf_probe_read_user(filename, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_printk("chown error reading filename");
        return 0;
    }
    filename[MAX_BUF_SIZE] = 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"chown\", filename=\"%s\", uid=\"%d\", gid=\"%d\"} ", pid,
                filename, (int)ctx->args[1], (int)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char source[MAX_BUF_SIZE + 1] = {0};
    char target[MAX_BUF_SIZE + 1] = {0};
    char fstype[MAX_BUF_SIZE + 1] = {0};

    bpf_probe_read_user(source, MAX_BUF_SIZE, (void*)ctx->args[0]);
    bpf_probe_read_user(target, MAX_BUF_SIZE, (void*)ctx->args[1]);
    bpf_probe_read_user(fstype, MAX_BUF_SIZE, (void*)ctx->args[2]);

    source[MAX_BUF_SIZE] = target[MAX_BUF_SIZE] = fstype[MAX_BUF_SIZE] = 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 200, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 200, "eptracer{pid=\"%d\", syscall=\"mount\", source=\"%s\", target=\"%s\", fstype=\"%s\", flags=\"%lx\", data=\"%p\"} ", pid,
                source, target, fstype, (unsigned long)ctx->args[3], (void*)ctx->args[4]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_decode(struct trace_event_raw_sys_enter *ctx)
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char target[MAX_BUF_SIZE + 1] = {0};
    long ret = bpf_probe_read_user(target, MAX_BUF_SIZE, (void*)ctx->args[0]);
    if (ret < 0) {
        bpf_printk("umount error reading target");
        return 0;
    }
    target[MAX_BUF_SIZE] = 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 100, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 100, "eptracer{pid=\"%d\", syscall=\"umount\", target=\"%s\", flags=\"%d\"}", pid,
                target, (int)ctx->args[1]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_ioctl")
int binder_ioctl_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    int fd = (int)ctx->args[0];
    unsigned long cmd = (unsigned long)ctx->args[1];

    #if defined(__ANDROID__) || defined(ANDROID_SMP) || defined(CONFIG_ANDROID)
        // Check if the ioctl is targeting /dev/binder (fd might be cached)
        if (cmd != BINDER_WRITE_READ && cmd != BINDER_SET_CONTEXT_MGR) 
            return 0;
    #endif

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 150, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 150, "eptracer{pid=\"%d\", syscall=\"binder_ioctl\", fd=\"%d\", cmd=\"%lu\", arg=\"%lu\"} ", pid, 
                fd, cmd, (unsigned long)ctx->args[2]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_setuid")
int setuid_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 80, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 80, "eptracer{pid=\"%d\", syscall=\"setuid\", uid=\"%d\"} ", pid, (int)ctx->args[0]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int setgid_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 80, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 80, "eptracer{pid=\"%d\", syscall=\"setgid\", gid=\"%d\"} ", pid, (int)ctx->args[0]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int capset_decode(struct trace_event_raw_sys_enter *ctx) 
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 120, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 120, "eptracer{pid=\"%d\", syscall=\"capset\", hdr=\"%p\", data=\"%p\"} ", pid,
                (void*)ctx->args[0], (void*)ctx->args[1]);
    bpf_ringbuf_submit(str_out, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int prctl_decode(struct trace_event_raw_sys_enter *ctx) 
{
   
    int pid = is_target_program();
    if (!pid) return 0;

    int option = (int)ctx->args[0];
    unsigned long arg2 = (unsigned long)ctx->args[1];

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 150, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 150, "eptracer{pid=\"%d\", syscall=\"prctl\", option=\"%d\", arg2=\"%lu\", arg3=\"%lu\", arg4=\"%lu\", arg5=\"%lu\"} ", pid,  
                option, arg2, (unsigned long)ctx->args[2], 
                (unsigned long)ctx->args[3], (unsigned long)ctx->args[4]);
    bpf_ringbuf_submit(str_out, 0);
 
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int keyctl_decode(struct trace_event_raw_sys_enter *ctx)
{
    
    int pid = is_target_program();
    if (!pid) return 0;

    int cmd = (int)ctx->args[0];
    unsigned long arg2 = (unsigned long)ctx->args[1];

    char *str_out = bpf_ringbuf_reserve(&syscall_rb_map, 120, 0);
    if (!str_out) return 0;

    BPF_SNPRINTF(str_out, 120, "eptracer{pid=\"%d\", syscall=\"keyctl\", cmd=\"%d\", arg2=\"%lu\", arg3=\"%lu\", arg4=\"%lu\", arg5=\"%lu\"} ", pid,  
                cmd, arg2, (unsigned long)ctx->args[2], 
                (unsigned long)ctx->args[3], (unsigned long)ctx->args[4]);
    bpf_ringbuf_submit(str_out, 0);
    
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
