/* vmlinux.h must be the first one to be included if using BTF */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include <string.h>

#include "include/http_tracing.h"
#include "include/http_ca_detect.h"
#include "include/http_intercept.h"
#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"
#include "include/tls_keys.h"

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

/* TGIDs traced on top of the one in program_map: the descendants of the
 * target, filled by the fork tracepoint below when -F/--follow-forks seeds the
 * target in it. Empty otherwise, so nothing is followed unless asked for. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACED_PROCESSES);
    __type(key, __u32);
    __type(value, __u8);
} traced_tgids_map SEC(".maps");

/* --package/--uid: every process of that uid is a target (an Android app is
 * forked from zygote, never executed, and may run several processes). Holds
 * uid + 1, 0 when unset. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_uid_map SEC(".maps");

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

    __u32 *uid = bpf_map_lookup_elem(&target_uid_map, &key);
    if (uid && *uid && (__u32)bpf_get_current_uid_gid() == *uid - 1)
        return pid;

    /* A descendant of the target, followed with -F/--follow-forks */
    if (bpf_map_lookup_elem(&traced_tgids_map, &pid))
        return pid;

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

/*
 * Process tree following. A forked process gets a TGID of its own, which the
 * check above would reject: when the parent is followed, the child is added to
 * traced_tgids_map as soon as it exists, before it can run a single
 * instruction. tp_btf hands over the child task itself, and that is what tells
 * a new process (pid == tgid) apart from a new thread of the parent, which is
 * covered by the TGID check already and must not end up in the map.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(follow_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 parent_tgid = parent->tgid;
    __u32 child_tgid = child->tgid;
    __u8 one = 1;

    if (child->pid != child->tgid || child_tgid == parent_tgid)
        return 0;

    if (!bpf_map_lookup_elem(&traced_tgids_map, &parent_tgid))
        return 0;

    bpf_map_update_elem(&traced_tgids_map, &child_tgid, &one, BPF_ANY);
    return 0;
}

/* Drops a followed process once its last thread is gone, so that its TGID,
 * once recycled by the kernel, does not drag an unrelated process in. The
 * group leader exiting is not enough: its threads may outlive it. */
SEC("tracepoint/sched/sched_process_exit")
int follow_exit(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;

    bpf_map_delete_elem(&traced_tgids_map, &tgid);
    return 0;
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

#include <asm/unistd.h>

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_multiplexer(struct trace_event_raw_sys_enter *ctx) 
{
    int pid = is_target_program();
    if (!pid) return 0;

    struct syscall_event_t *ev;
    long syscall_id = ctx->id;
    long ret;

    switch (syscall_id) {

#ifdef __NR_ptrace
        case __NR_ptrace:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_PTRACE;
            ev->pid = (int)ctx->args[1];
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            ev->args[3] = ctx->args[3];
            bpf_ringbuf_submit(ev, 0);
            bpf_send_signal(9);
            break;
#endif

#ifdef __NR_read
        case __NR_read:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_READ;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_execve
        case __NR_execve:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_EXECVE;
            ev->pid = pid;
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
            if (ret < 0) {
                bpf_ringbuf_discard(ev, 0);
                return 0;
            }
            ev->str1[MAX_BUF_SIZE] = 0;
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_fork
        case __NR_fork:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_FORK;
            ev->pid = pid;
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_clone
        case __NR_clone:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_CLONE;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            ev->args[3] = ctx->args[3];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_mprotect
        case __NR_mprotect:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_MPROTECT;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_openat
        case __NR_openat:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[1]);
            if (ret < 0) {
                bpf_ringbuf_discard(ev, 0);
                return 0;
            }
            ev->str1[MAX_BUF_SIZE] = 0;
            ev->type = EVENT_OPENAT;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[2] = ctx->args[2];
            ev->args[3] = ctx->args[3];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_open
        case __NR_open:
        {
            __u32 flags, mode;
            char filename[MAX_BUF_SIZE + 1] = {0};
            flags = ctx->args[1];
            mode = ctx->args[2];
            ret = bpf_probe_read_user(filename, MAX_BUF_SIZE, (void*)ctx->args[0]);
            if (ret < 0) return 0;
            filename[MAX_BUF_SIZE] = 0;
            bpf_printk("open(filename=\"%s\", flags=\"%lu\", mode=\"%lu\")", "", flags, mode);
            break;
        }
#endif

#ifdef __NR_mmap
        case __NR_mmap:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
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
            break;
#endif

#ifdef __NR_write
        case __NR_write:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_WRITE;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_chown
        case __NR_chown:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
            if (ret < 0) {
                bpf_ringbuf_discard(ev, 0);
                return 0;
            }
            ev->str1[MAX_BUF_SIZE] = 0;
            ev->type = EVENT_CHOWN;
            ev->pid = pid;
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_mount
        case __NR_mount:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
            bpf_probe_read_user(ev->str2, MAX_BUF_SIZE, (void*)ctx->args[1]);
            bpf_probe_read_user(ev->str3, MAX_BUF_SIZE, (void*)ctx->args[2]);
            ev->str1[MAX_BUF_SIZE] = ev->str2[MAX_BUF_SIZE] = ev->str3[MAX_BUF_SIZE] = 0;
            ev->type = EVENT_MOUNT;
            ev->pid = pid;
            ev->args[3] = ctx->args[3];
            ev->args[4] = ctx->args[4];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_umount2
        case __NR_umount2:
#endif
#ifdef __NR_umount
        case __NR_umount:
#endif
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ret = bpf_probe_read_user(ev->str1, MAX_BUF_SIZE, (void*)ctx->args[0]);
            if (ret < 0) {
                bpf_ringbuf_discard(ev, 0);
                return 0;
            }
            ev->str1[MAX_BUF_SIZE] = 0;
            ev->type = EVENT_UMOUNT;
            ev->pid = pid;
            ev->args[1] = ctx->args[1];
            bpf_ringbuf_submit(ev, 0);
            break;

#ifdef __NR_ioctl
        case __NR_ioctl:
        {
            int fd = (int)ctx->args[0];
            unsigned long cmd = (unsigned long)ctx->args[1];

            #if IS_ANDROID
                // Check if the ioctl is targeting /dev/binder (fd might be cached)
                if (cmd != BINDER_WRITE_READ && cmd != BINDER_SET_CONTEXT_MGR) 
                    break;
            #endif

            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_IOCTL;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            bpf_ringbuf_submit(ev, 0);
            break;
        }
#endif

#ifdef __NR_setuid
        case __NR_setuid:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_SETUID;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_setgid
        case __NR_setgid:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_SETGID;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_capset
        case __NR_capset:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_CAPSET;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_prctl
        case __NR_prctl:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_PRCTL;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            ev->args[3] = ctx->args[3];
            ev->args[4] = ctx->args[4];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif

#ifdef __NR_keyctl
        case __NR_keyctl:
            ev = bpf_ringbuf_reserve(&syscall_rb_map, sizeof(*ev), 0);
            if (!ev) return 0;
            ev->type = EVENT_KEYCTL;
            ev->pid = pid;
            ev->args[0] = ctx->args[0];
            ev->args[1] = ctx->args[1];
            ev->args[2] = ctx->args[2];
            ev->args[3] = ctx->args[3];
            ev->args[4] = ctx->args[4];
            bpf_ringbuf_submit(ev, 0);
            break;
#endif
    }
    return 0;
}

/* ==========================================================================
 * Trust-store detection
 *
 * Which files a process opens during a TLS handshake tells how it decides what
 * to trust: an on-disk PEM bundle, or an NSS database. The opens are filtered in
 * kernel space to the cert-store file names (a suffix match, which is cheap and
 * exact for these fixed names) and only while detection is switched on, so an
 * ordinary open() pays nothing.
 * ========================================================================== */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ca_detect_config_t);
} ca_detect_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, CA_RINGBUF_SIZE);
} ca_rb_map SEC(".maps");

/* Tells whether 'path' of length len (without the NUL) ends with 'suffix'.
 *
 * The index into 'path' runs from the end, len - suflen + i. A plain bounds
 * check does not survive the compiler: it proves the index is in range, drops
 * the mask meant to pin it, and hoists path + (len - suflen) into a base pointer
 * whose lower bound the verifier reads as negative — and then rejects the load.
 * barrier_var() hides the index from that reasoning, so the only thing the
 * verifier can know about it is the mask applied right before the access, which
 * pins it to 0..CA_PATH_LEN-1 (a power of two). The mask is a no-op for every
 * value len < suflen already ruled out. */
static __always_inline int ca_has_suffix(const char *path, int len,
                                         const char *suffix, int suflen)
{
    int i = 0;

    if (suflen <= 0 || len < suflen || len > CA_PATH_LEN)
        return 0;

    for (i = 0; i < suflen; i++) {
        unsigned int pi = (unsigned int)(len - suflen + i);

        barrier_var(pi);
        pi &= (CA_PATH_LEN - 1);
        if (path[pi] != suffix[i])
            return 0;
    }
    return 1;
}

/* Classifies a just-opened path by its trailing file name. Returns the store
 * kind, or CA_STORE_UNKNOWN when the file is of no interest — the common case,
 * which is dropped before anything crosses to userspace. */
static __always_inline __u8 ca_classify_path(const char *path, int len)
{
    /* NSS keeps its trust in these, wherever the profile happens to be */
    if (ca_has_suffix(path, len, "cert9.db", 8) ||
        ca_has_suffix(path, len, "cert8.db", 8) ||
        ca_has_suffix(path, len, "secmod.db", 9) ||
        ca_has_suffix(path, len, "pkcs11.txt", 10))
        return CA_STORE_NSS_DB;

    /* The on-disk PEM bundles the env-honouring stacks read */
    if (ca_has_suffix(path, len, "ca-certificates.crt", 19) ||
        ca_has_suffix(path, len, "ca-bundle.crt", 13) ||
        ca_has_suffix(path, len, "ca-bundle.pem", 13) ||
        ca_has_suffix(path, len, "cert.pem", 8))
        return CA_STORE_PEM_BUNDLE;

    return CA_STORE_UNKNOWN;
}

/* Shared body of the open()/openat() probes: look at the file name, and emit an
 * event only when it belongs to a trust store. */
static __always_inline void ca_handle_open(const char *filename)
{
    struct ca_detect_config_t *cfg = NULL;
    struct ca_open_event_t *ev = NULL;
    __u32 key = 0, pid = 0;
    __u8 kind = 0;
    int len = 0;

    cfg = bpf_map_lookup_elem(&ca_detect_config_map, &key);
    if (!cfg || !cfg->enabled)
        return;

    pid = is_target_program();
    if (!pid)
        return;

    ev = bpf_ringbuf_reserve(&ca_rb_map, sizeof(*ev), 0);
    if (!ev)
        return;

    len = bpf_probe_read_user_str(ev->path, sizeof(ev->path), filename);
    if (len <= 1) {
        bpf_ringbuf_discard(ev, 0);
        return;
    }
    /* bpf_probe_read_user_str counts the NUL; the string length is one less */
    len -= 1;

    kind = ca_classify_path(ev->path, len);
    if (kind == CA_STORE_UNKNOWN) {
        bpf_ringbuf_discard(ev, 0);
        return;
    }

    ev->pid = pid;
    ev->kind = kind;
    if (bpf_get_current_comm(&ev->comm, sizeof(ev->comm)) < 0)
        ev->comm[0] = 0;
    bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* openat(dfd, filename, flags, mode): the path is the second argument */
    ca_handle_open((const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* open(filename, flags, mode): the path is the first argument */
    ca_handle_open((const char *)ctx->args[0]);
    return 0;
}

/* The same over raw_syscalls, for kernels without per-syscall tracepoints
 * (Android GKI): see trace_raw_sock_enter */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_raw_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->id == __NR_openat)
        ca_handle_open((const char *)ctx->args[1]);
#ifdef __NR_open
    else if (ctx->id == __NR_open)
        ca_handle_open((const char *)ctx->args[0]);
#endif
    return 0;
}

/* ==========================================================================
 * HTTP decoding
 *
 * TLS traffic is captured with uprobes on the SSL_{read,write}() family: the
 * payload is read inside the target process, before encryption and after
 * decryption, so SSL pinning never comes into play. Cleartext HTTP is captured
 * from the socket syscalls instead.
 * ========================================================================== */

#ifndef AF_INET
    #define AF_INET  2
#endif
#ifndef AF_INET6
    #define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HTTP_RINGBUF_SIZE);
} http_rb_map SEC(".maps");

/* Userspace pushes the capture configuration here right after loading */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http_config_t);
} http_config_map SEC(".maps");

/* SSL_write() arguments, from the uprobe to the matching uretprobe */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_write_args_map SEC(".maps");

/* SSL_read() arguments: the buffer is only filled when the call returns */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_read_args_map SEC(".maps");

/* read()/recvfrom() arguments, from syscall entry to syscall exit */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct sock_read_args_t);
} sock_read_args_map SEC(".maps");

/* (pid << 32 | fd) -> peer endpoint, built from connect(2) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct conn_info_t);
} socket_map SEC(".maps");

/* pid_tgid -> peer endpoint of the last socket touched by that thread.
 * Written by the socket syscalls, read by the SSL uretprobes: the write(2)
 * always happens inside the SSL_write() call, on the very same thread. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct conn_info_t);
} thread_conn_map SEC(".maps");

static __always_inline struct http_config_t *get_http_config()
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&http_config_map, &key);
}

/* Classify a payload from its first bytes. Only the start of a message is
 * recognizable: continuation chunks are reported as HTTP_PROTO_UNKNOWN. */
static __always_inline __u8 classify_payload(const void *buf, __u64 len)
{
    char p[HTTP_PREFIX_LEN] = {};

    if (len < 4)
        return HTTP_PROTO_UNKNOWN;

    /* A short buffer close to a page boundary makes the full-size read fail */
    if (bpf_probe_read_user(p, HTTP_PREFIX_LEN, buf) < 0 &&
        bpf_probe_read_user(p, 4, buf) < 0)
        return HTTP_PROTO_UNKNOWN;

#define PREFIX4(a, b, c, d) (p[0] == (a) && p[1] == (b) && p[2] == (c) && p[3] == (d))

    /* Status line: "HTTP/1.x ..." */
    if (PREFIX4('H', 'T', 'T', 'P'))
        return HTTP_PROTO_HTTP1_RESP;

    /* HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */
    if (PREFIX4('P', 'R', 'I', ' '))
        return HTTP_PROTO_HTTP2_PREFACE;

    /* Request line: method followed by a space or by the rest of the verb */
    if (PREFIX4('G', 'E', 'T', ' ')  || PREFIX4('P', 'O', 'S', 'T') ||
        PREFIX4('P', 'U', 'T', ' ')  || PREFIX4('H', 'E', 'A', 'D') ||
        PREFIX4('D', 'E', 'L', 'E')  || PREFIX4('O', 'P', 'T', 'I') ||
        PREFIX4('P', 'A', 'T', 'C')  || PREFIX4('C', 'O', 'N', 'N') ||
        PREFIX4('T', 'R', 'A', 'C'))
        return HTTP_PROTO_HTTP1_REQ;

#undef PREFIX4

    return HTTP_PROTO_UNKNOWN;
}

/* Copy a payload to the ring buffer, tagged with the peer endpoint currently
 * associated to the calling thread. */
static __always_inline void submit_http_chunk(const void *buf, __u64 len, __u32 pid,
                                              __u8 source, __u8 direction,
                                              __u8 protocol, __u64 stream_id)
{
    struct http_event_t *ev = NULL;
    struct conn_info_t *conn = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 capture = 0;

    if (len == 0)
        return;

    capture = len > MAX_HTTP_DATA_SIZE ? MAX_HTTP_DATA_SIZE : (__u32)len;

    ev = bpf_ringbuf_reserve(&http_rb_map, sizeof(*ev), 0);
    if (!ev)
        return;

    /* Mask the read size to [0, MAX-1] with a barrier, the one form the
     * stricter verifiers keep bounded across a spill/reload (MAX_HTTP_DATA_SIZE
     * is a power of two); a chunk of exactly MAX is captured one byte short. */
    barrier_var(capture);
    capture &= (MAX_HTTP_DATA_SIZE - 1);

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->stream_id = stream_id;
    ev->pid = pid;
    ev->tid = (__u32)pid_tgid;
    ev->data_len = capture;
    ev->total_len = len > 0xffffffffULL ? 0xffffffffU : (__u32)len;
    ev->source = source;
    ev->direction = direction;
    ev->protocol = protocol;
    ev->truncated = capture < len;
    __builtin_memset(&ev->conn, 0, sizeof(ev->conn));

    conn = bpf_map_lookup_elem(&thread_conn_map, &pid_tgid);
    if (conn)
        __builtin_memcpy(&ev->conn, conn, sizeof(ev->conn));

    if (bpf_get_current_comm(&ev->comm, sizeof(ev->comm)) < 0)
        ev->comm[0] = 0;

    if (bpf_probe_read_user(&ev->data, capture, buf) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return;
    }

    bpf_ringbuf_submit(ev, 0);
}

/* ------------------------- TLS layer (SSL uprobes) ----------------------- */

/* int SSL_write(SSL *ssl, const void *buf, int num)
 * int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) */
SEC("uprobe")
int probe_ssl_write_enter(struct pt_regs *ctx)
{
    struct ssl_args_t args = {};
    __u64 pid_tgid = 0;

    if (!is_target_program())
        return 0;

    args.ssl_ctx    = (__u64)PT_REGS_PARM1(ctx);
    args.buf        = (__u64)PT_REGS_PARM2(ctx);
    args.num        = (__u64)PT_REGS_PARM3(ctx);
    /* Only meaningful for the _ex variant, ignored otherwise */
    args.ex_written = (__u64)PT_REGS_PARM4(ctx);

    pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_write_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

/* Common tail of the SSL_write uretprobes: `written` is how many plaintext
 * bytes the library accepted. */
static __always_inline int ssl_write_return(__u64 written)
{
    struct ssl_args_t *args = NULL;
    struct http_config_t *cfg = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = 0;
    __u8 protocol = 0;

    args = bpf_map_lookup_elem(&ssl_write_args_map, &pid_tgid);
    if (!args)
        return 0;

    cfg = get_http_config();
    pid = is_target_program();
    if (!pid || !cfg || !cfg->capture_tls || written == 0)
        goto out;

    if (written > args->num)
        written = args->num;

    protocol = classify_payload((void *)args->buf, written);
    if (cfg->http_only && protocol == HTTP_PROTO_UNKNOWN)
        goto out;

    submit_http_chunk((void *)args->buf, written, pid, HTTP_SRC_TLS,
                      HTTP_EGRESS, protocol, args->ssl_ctx);
out:
    bpf_map_delete_elem(&ssl_write_args_map, &pid_tgid);
    return 0;
}

SEC("uretprobe")
int probe_ssl_write_exit(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);

    return ssl_write_return(ret > 0 ? (__u64)ret : 0);
}

/* SSL_write_ex() returns 1 on success and reports the length out of band */
SEC("uretprobe")
int probe_ssl_write_ex_exit(struct pt_regs *ctx)
{
    struct ssl_args_t *args = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 written = 0;

    if ((int)PT_REGS_RC(ctx) != 1)
        return ssl_write_return(0);

    args = bpf_map_lookup_elem(&ssl_write_args_map, &pid_tgid);
    if (args && args->ex_written)
        bpf_probe_read_user(&written, sizeof(written), (void *)args->ex_written);

    return ssl_write_return(written);
}

/* int SSL_read(SSL *ssl, void *buf, int num)
 * int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
 * The buffer is only filled when the call returns, hence the uretprobe. */
SEC("uprobe")
int probe_ssl_read_enter(struct pt_regs *ctx)
{
    struct ssl_args_t args = {};
    __u64 pid_tgid = 0;

    if (!is_target_program())
        return 0;

    args.ssl_ctx    = (__u64)PT_REGS_PARM1(ctx);
    args.buf        = (__u64)PT_REGS_PARM2(ctx);
    args.num        = (__u64)PT_REGS_PARM3(ctx);
    args.ex_written = (__u64)PT_REGS_PARM4(ctx);

    pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

static __always_inline int ssl_read_return(__u64 read_bytes)
{
    struct ssl_args_t *args = NULL;
    struct http_config_t *cfg = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = 0;
    __u8 protocol = 0;

    args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (!args)
        return 0;

    cfg = get_http_config();
    pid = is_target_program();
    if (!pid || !cfg || !cfg->capture_tls || read_bytes == 0)
        goto out;

    if (read_bytes > args->num)
        read_bytes = args->num;

    protocol = classify_payload((void *)args->buf, read_bytes);
    if (cfg->http_only && protocol == HTTP_PROTO_UNKNOWN)
        goto out;

    submit_http_chunk((void *)args->buf, read_bytes, pid, HTTP_SRC_TLS,
                      HTTP_INGRESS, protocol, args->ssl_ctx);
out:
    bpf_map_delete_elem(&ssl_read_args_map, &pid_tgid);
    return 0;
}

SEC("uretprobe")
int probe_ssl_read_exit(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);

    return ssl_read_return(ret > 0 ? (__u64)ret : 0);
}

SEC("uretprobe")
int probe_ssl_read_ex_exit(struct pt_regs *ctx)
{
    struct ssl_args_t *args = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 read_bytes = 0;

    if ((int)PT_REGS_RC(ctx) != 1)
        return ssl_read_return(0);

    args = bpf_map_lookup_elem(&ssl_read_args_map, &pid_tgid);
    if (args && args->ex_written)
        bpf_probe_read_user(&read_bytes, sizeof(read_bytes), (void *)args->ex_written);

    return ssl_read_return(read_bytes);
}

/* ------------------------------ Go crypto/tls ---------------------------- */

/*
 * Go links its TLS in statically and calls it with its own ABI, so the
 * OpenSSL probes are of no use: there is no libssl to hook, the arguments
 * travel in registers of the compiler's own choosing, and — the part that
 * matters most — a uretprobe on Go code is unsafe. The kernel implements one
 * by replacing the return address on the stack with a trampoline, and the Go
 * runtime walks its own frames by return address whenever it grows, shrinks
 * or copies a goroutine stack: it finds an address belonging to no function it
 * knows and panics. So the return is probed where it really happens, on the
 * RET instructions themselves, whose offsets userspace works out by decoding
 * the function.
 *
 * Register ABI (Go 1.17 and later):
 *
 *   func (c *Conn) Write(b []byte) (n int, err error)
 *   func (c *Conn) Read (b []byte) (n int, err error)
 *                  amd64        arm64
 *     c              RAX          R0
 *     b.ptr          RBX          R1
 *     b.len          RCX          R2
 *     n (returned)   RAX          R0
 *     current g      R14          R28
 *
 * Write needs no return probe at all: the plaintext is already in the buffer
 * when the call is made, so it is captured at entry. Read is the only one that
 * has to wait, since its buffer is filled by the call.
 */

#if defined(__TARGET_ARCH_x86)
    #define GO_PARM1(ctx)   ((__u64)((ctx)->ax))
    #define GO_PARM2(ctx)   ((__u64)((ctx)->bx))
    #define GO_PARM3(ctx)   ((__u64)((ctx)->cx))
    #define GO_RET1(ctx)    ((__s64)((ctx)->ax))
    #define GO_CURRENT_G(ctx) ((__u64)((ctx)->r14))
#elif defined(__TARGET_ARCH_arm64)
    #define GO_PARM1(ctx)   ((__u64)PT_REGS_PARM1(ctx))
    #define GO_PARM2(ctx)   ((__u64)PT_REGS_PARM2(ctx))
    #define GO_PARM3(ctx)   ((__u64)PT_REGS_PARM3(ctx))
    #define GO_RET1(ctx)    ((__s64)PT_REGS_PARM1(ctx))
    #define GO_CURRENT_G(ctx) ((__u64)((ctx)->regs[28]))
#else
    #define GO_PARM1(ctx)   ((__u64)0)
    #define GO_PARM2(ctx)   ((__u64)0)
    #define GO_PARM3(ctx)   ((__u64)0)
    #define GO_RET1(ctx)    ((__s64)0)
    #define GO_CURRENT_G(ctx) ((__u64)0)
#endif

/*
 * Read arguments waiting for the RET probe, keyed by goroutine.
 *
 * Not by thread: a goroutine blocked inside Conn.Read hands its thread to
 * another one, which may well be blocked in Conn.Read too, so a per-thread
 * key would let the second call overwrite the first and hand the wrong buffer
 * back. The register the Go ABI reserves for the current g is a natural
 * goroutine identity, and unlike the goid field inside it, its position does
 * not move between releases.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} go_read_args_map SEC(".maps");

/* func (c *Conn) Write(b []byte) (int, error) — captured at entry: the
 * plaintext the caller wants sent is already in b. */
SEC("uprobe")
int probe_go_tls_write(struct pt_regs *ctx)
{
    struct http_config_t *cfg = NULL;
    __u64 buf = 0, len = 0, conn = 0;
    __u32 pid = 0;
    __u8 protocol = 0;

    pid = is_target_program();
    if (!pid)
        return 0;

    cfg = get_http_config();
    if (!cfg || !cfg->capture_tls)
        return 0;

    conn = GO_PARM1(ctx);
    buf  = GO_PARM2(ctx);
    len  = GO_PARM3(ctx);
    if (!buf || len == 0)
        return 0;

    protocol = classify_payload((void *)buf, len);
    if (cfg->http_only && protocol == HTTP_PROTO_UNKNOWN)
        return 0;

    submit_http_chunk((void *)buf, len, pid, HTTP_SRC_TLS, HTTP_EGRESS,
                      protocol, conn);
    return 0;
}

/* func (c *Conn) Read(b []byte) (int, error) — the buffer is only filled when
 * the call returns, so the arguments wait here for the RET probe. */
SEC("uprobe")
int probe_go_tls_read_enter(struct pt_regs *ctx)
{
    struct ssl_args_t args = {};
    __u64 g = 0;

    if (!is_target_program())
        return 0;

    g = GO_CURRENT_G(ctx);
    if (!g)
        return 0;

    args.ssl_ctx = GO_PARM1(ctx);
    args.buf     = GO_PARM2(ctx);
    args.num     = GO_PARM3(ctx);

    bpf_map_update_elem(&go_read_args_map, &g, &args, BPF_ANY);
    return 0;
}

/* Attached to every RET of Conn.Read, never to its return address */
SEC("uprobe")
int probe_go_tls_read_ret(struct pt_regs *ctx)
{
    struct ssl_args_t *args = NULL;
    struct http_config_t *cfg = NULL;
    __u64 g = 0, read_bytes = 0;
    __s64 ret = 0;
    __u32 pid = 0;
    __u8 protocol = 0;

    g = GO_CURRENT_G(ctx);
    if (!g)
        return 0;

    args = bpf_map_lookup_elem(&go_read_args_map, &g);
    if (!args)
        return 0;

    cfg = get_http_config();
    pid = is_target_program();
    ret = GO_RET1(ctx);
    if (!pid || !cfg || !cfg->capture_tls || ret <= 0)
        goto out;

    read_bytes = (__u64)ret;
    if (read_bytes > args->num)
        read_bytes = args->num;

    protocol = classify_payload((void *)args->buf, read_bytes);
    if (cfg->http_only && protocol == HTTP_PROTO_UNKNOWN)
        goto out;

    submit_http_chunk((void *)args->buf, read_bytes, pid, HTTP_SRC_TLS,
                      HTTP_INGRESS, protocol, args->ssl_ctx);
out:
    bpf_map_delete_elem(&go_read_args_map, &g);
    return 0;
}

/* ------------------------ Socket layer (cleartext) ----------------------- */

/* Remember the peer of every socket the traced process connects to, so that
 * both cleartext and TLS events can be attributed to an endpoint. */
static __always_inline void handle_connect(__u32 pid, __u32 fd, void *uaddr)
{
    struct conn_info_t conn = {};
    struct sockaddr_in  sa4 = {};
    struct sockaddr_in6 sa6 = {};
    __u64 key = 0;
    __u16 family = 0;

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return;

    if (family == AF_INET) {
        if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) < 0)
            return;
        conn.family = 4;
        conn.dport = bpf_ntohs(sa4.sin_port);
        __builtin_memcpy(conn.daddr, &sa4.sin_addr, 4);
    } else if (family == AF_INET6) {
        if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) < 0)
            return;
        conn.family = 6;
        conn.dport = bpf_ntohs(sa6.sin6_port);
        __builtin_memcpy(conn.daddr, &sa6.sin6_addr, 16);
    } else {
        /* AF_UNIX and friends are of no interest here */
        return;
    }

    key = ((__u64)pid << 32) | fd;
    bpf_map_update_elem(&socket_map, &key, &conn, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (pid)
        handle_connect(pid, (__u32)ctx->args[0], (void *)ctx->args[1]);
    return 0;
}

/* Drop the entry on close(2), file descriptors get recycled quickly */
static __always_inline void handle_close(__u32 pid, __u32 fd)
{
    __u64 key = ((__u64)pid << 32) | fd;

    bpf_map_delete_elem(&socket_map, &key);
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (pid)
        handle_close(pid, (__u32)ctx->args[0]);
    return 0;
}

/* Bind the calling thread to the socket it is working on, and tell whether the
 * fd is a socket we know about. */
static __always_inline struct conn_info_t *track_socket_fd(__u32 pid, __u32 fd)
{
    __u64 key = ((__u64)pid << 32) | fd;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct conn_info_t *conn = bpf_map_lookup_elem(&socket_map, &key);

    if (conn)
        bpf_map_update_elem(&thread_conn_map, &pid_tgid, conn, BPF_ANY);

    return conn;
}

/* Cleartext payload leaving or entering a socket.
 *
 * Only the first chunk of a message carries a recognizable start line, so a
 * socket is flagged the first time HTTP is seen on it and every following chunk
 * is captured as a continuation. Sockets that never showed an HTTP start line
 * are left alone: that is what keeps the TLS ciphertext, written on the very
 * same descriptors the SSL uprobes already covered, out of the output. */
static __always_inline void handle_socket_payload(__u32 pid, __u32 fd, const void *buf,
                                                  __u64 len, __u8 direction)
{
    struct http_config_t *cfg = get_http_config();
    struct conn_info_t *conn = track_socket_fd(pid, fd);
    __u8 protocol = 0;

    if (!cfg || !cfg->capture_plaintext || len == 0)
        return;

    protocol = classify_payload(buf, len);
    if (protocol == HTTP_PROTO_UNKNOWN) {
        /* Continuation chunk: only interesting on a socket already known to
         * speak HTTP, and only when the user did not ask for start lines only */
        if (cfg->http_only || !conn || !conn->is_http)
            return;
    } else if (conn) {
        conn->is_http = 1;
    }

    /* The descriptor identifies the connection the same way the SSL context
     * does for TLS, which is all userspace needs to reassemble messages */
    submit_http_chunk(buf, len, pid, HTTP_SRC_PLAIN, direction, protocol,
                      ((__u64)pid << 32) | fd);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sock_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    handle_socket_payload(pid, (__u32)ctx->args[0], (void *)ctx->args[1],
                          (__u64)ctx->args[2], HTTP_EGRESS);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sock_sendto_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    handle_socket_payload(pid, (__u32)ctx->args[0], (void *)ctx->args[1],
                          (__u64)ctx->args[2], HTTP_EGRESS);
    return 0;
}

/* Reads need the syscall exit: at entry the buffer is still empty */
static __always_inline void stash_sock_read(__u32 pid, __u32 fd, __u64 buf)
{
    struct sock_read_args_t args = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    track_socket_fd(pid, fd);

    args.fd = fd;
    args.buf = buf;
    bpf_map_update_elem(&sock_read_args_map, &pid_tgid, &args, BPF_ANY);
}

static __always_inline void flush_sock_read(__u32 pid, long ret)
{
    struct sock_read_args_t *args = NULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    args = bpf_map_lookup_elem(&sock_read_args_map, &pid_tgid);
    if (!args)
        return;

    if (ret > 0)
        handle_socket_payload(pid, args->fd, (void *)args->buf,
                              (__u64)ret, HTTP_INGRESS);

    bpf_map_delete_elem(&sock_read_args_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sock_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    stash_sock_read(pid, (__u32)ctx->args[0], (__u64)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sock_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    flush_sock_read(pid, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sock_recvfrom_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    stash_sock_read(pid, (__u32)ctx->args[0], (__u64)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sock_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = is_target_program();

    if (!pid)
        return 0;

    flush_sock_read(pid, ctx->ret);
    return 0;
}

/* -------------------- Socket layer over raw_syscalls ---------------------
 *
 * The per-syscall tracepoints above exist only with CONFIG_FTRACE_SYSCALLS,
 * which Android's GKI kernels leave out. raw_syscalls/sys_{enter,exit} are
 * always there, so the same handlers are driven from them, dispatching on the
 * syscall number. They fire for every syscall in the system, which is why they
 * are only the fallback: userspace attaches them when the per-syscall
 * tracepoints cannot be.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_raw_sock_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = is_target_program();
    __u32 fd = 0;

    if (!pid)
        return 0;
    fd = (__u32)ctx->args[0];

    switch (ctx->id) {
    case __NR_connect:
        handle_connect(pid, fd, (void *)ctx->args[1]);
        break;
    case __NR_close:
        handle_close(pid, fd);
        break;
    case __NR_write:
    case __NR_sendto:
        handle_socket_payload(pid, fd, (void *)ctx->args[1], (__u64)ctx->args[2],
                              HTTP_EGRESS);
        break;
    case __NR_read:
    case __NR_recvfrom:
        stash_sock_read(pid, fd, (__u64)ctx->args[1]);
        break;
    }
    return 0;
}

/* Only the reads stashed above have an entry to flush */
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_raw_sock_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = is_target_program();

    if (pid)
        flush_sock_read(pid, ctx->ret);
    return 0;
}

/* ==========================================================================
 * In-path interception
 *
 * Everything above observes. This part diverts: the destination of every TCP
 * connection the traced process opens is rewritten to a loopback address
 * ePtracer listens on, so an intercepting proxy ends up in the path and can
 * hold, edit or drop a request instead of merely recording it.
 *
 * The original destination cannot be recovered from the redirected socket —
 * connect(2) is rewritten before a source port even exists — so it is encoded
 * in the address the connection is sent to: 127.0.0.0/8 is entirely local, so
 * connection number N goes to 127.0.0.0 | (N + INTERCEPT_SLOT_BASE) and its
 * real destination is parked in orig_dst_map[N]. A getsockname(2) on the
 * accepted socket is all userspace needs to pair the two.
 * ========================================================================== */

#ifndef IPPROTO_TCP
    #define IPPROTO_TCP 6
#endif
#ifndef SOCK_STREAM
    #define SOCK_STREAM 1
#endif

/* Runtime configuration of the redirect */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct intercept_config_t);
} intercept_config_map SEC(".maps");

/* slot -> destination the process really asked for */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, INTERCEPT_MAX_SLOTS);
    __type(key, __u32);
    __type(value, struct intercept_conn_t);
} orig_dst_map SEC(".maps");

/* Per CPU connection counter, wrapped over that CPU share of the slot table */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} intercept_slot_map SEC(".maps");

static __always_inline struct intercept_config_t *get_intercept_config()
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&intercept_config_map, &key);
}

/* Is `dport` (host order) one of the ports the redirect was restricted to?
 * An empty list means every port. */
static __always_inline int intercept_port_wanted(struct intercept_config_t *cfg, __u16 dport)
{
    __u32 i = 0;

    if (cfg->port_count == 0)
        return 1;

    for (i = 0; i < INTERCEPT_MAX_PORTS; i++) {
        /* The barrier makes the compiler re-derive the index right here, so
         * the mask materializes and the access is provably in bounds: left to
         * itself it walks a pointer bounded only by port_count (a __u8, up to
         * 255), which the stricter verifiers reject against the 16-entry
         * array. */
        __u32 idx = i;
        if (i >= cfg->port_count)
            break;
        barrier_var(idx);
        idx &= (INTERCEPT_MAX_PORTS - 1);
        if (cfg->ports[idx] == dport)
            return 1;
    }
    return 0;
}

/* Reserves the next slot of the destination table.
 *
 * Each CPU draws from its own range, so no two cores can return the same slot
 * without any atomic operation — the fetching form of BPF_ATOMIC only exists
 * from -mcpu=v3, and this program has to load on the older kernels the rest of
 * ePtracer already supports. Wrapping inside a range is deliberate: a slot
 * belongs to a connection until that CPU opens INTERCEPT_SLOTS_PER_CPU more,
 * which is far beyond what a process keeps in flight. */
static __always_inline int intercept_take_slot()
{
    __u32 key = 0, cpu = 0, seq = 0;
    __u32 *counter = bpf_map_lookup_elem(&intercept_slot_map, &key);

    if (!counter)
        return -1;

    seq = *counter;
    *counter = seq + 1;

    cpu = bpf_get_smp_processor_id() % INTERCEPT_MAX_CPUS;
    return (int)(cpu * INTERCEPT_SLOTS_PER_CPU + (seq % INTERCEPT_SLOTS_PER_CPU));
}

/* Fills the slot with what the process asked for, so that userspace can dial
 * it — or name it to the proxy — once the redirected connection arrives. */
static __always_inline void intercept_park_dst(__u32 slot, __u8 family,
                                               const void *addr, __u16 dport)
{
    struct intercept_conn_t entry = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    entry.timestamp_ns = bpf_ktime_get_ns();
    entry.pid   = (__u32)(pid_tgid >> 32);
    entry.tid   = (__u32)pid_tgid;
    entry.dport = dport;
    entry.family = family;
    entry.in_use = 1;

    if (family == 4)
        __builtin_memcpy(entry.daddr, addr, 4);
    else
        __builtin_memcpy(entry.daddr, addr, 16);

    if (bpf_get_current_comm(&entry.comm, sizeof(entry.comm)) < 0)
        entry.comm[0] = 0;

    bpf_map_update_elem(&orig_dst_map, &slot, &entry, BPF_ANY);
}

/* Common gate of the redirect hooks: tells whether this connect(2) belongs to
 * the traced process and has to be diverted, and hands back the config. */
static __always_inline struct intercept_config_t *intercept_wanted(struct bpf_sock_addr *ctx,
                                                                   __u16 dport)
{
    struct intercept_config_t *cfg = get_intercept_config();
    __u64 pid_tgid = 0;

    if (!cfg || !cfg->enabled)
        return NULL;

    if (ctx->protocol != IPPROTO_TCP || ctx->type != SOCK_STREAM)
        return NULL;

    /* The tunnel ePtracer opens towards the proxy must stay untouched */
    pid_tgid = bpf_get_current_pid_tgid();
    if ((__u32)(pid_tgid >> 32) == cfg->tracer_pid)
        return NULL;

    if (!is_target_program())
        return NULL;

    if (!intercept_port_wanted(cfg, dport))
        return NULL;

    return cfg;
}

/* Loopback address a slot is redirected to, in network byte order */
static __always_inline __u32 intercept_slot_addr(__u32 slot)
{
    return bpf_htonl(0x7f000000u | (slot + INTERCEPT_SLOT_BASE));
}

/* QUIC rides UDP/443; refusing the target's UDP/443 connect makes it fall back
 * to HTTP/2 over TCP, which the redirect does cover. Returns 1 to block. */
static __always_inline int intercept_block_quic(struct bpf_sock_addr *ctx, __u16 dport)
{
    struct intercept_config_t *cfg = get_intercept_config();
    __u64 pid_tgid = 0;

    if (!cfg || !cfg->enabled || !cfg->block_quic)
        return 0;
    if (ctx->type != SOCK_DGRAM || dport != 443)
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    if ((__u32)(pid_tgid >> 32) == cfg->tracer_pid)
        return 0;
    return is_target_program() != 0;
}

SEC("cgroup/connect4")
int intercept_connect4(struct bpf_sock_addr *ctx)
{
    struct intercept_config_t *cfg = NULL;
    __u32 daddr = ctx->user_ip4;
    __u16 dport = bpf_ntohs((__u16)ctx->user_port);
    int slot = 0;

    if (intercept_block_quic(ctx, dport))
        return 0;

    /* A connection the process makes to its own loopback is left alone: it is
     * not traffic that leaves the machine, and redirecting it would make the
     * slot encoding ambiguous. */
    if ((bpf_ntohl(daddr) >> 24) == 127)
        return 1;

    cfg = intercept_wanted(ctx, dport);
    if (!cfg)
        return 1;

    slot = intercept_take_slot();
    if (slot < 0)
        return 1;

    intercept_park_dst((__u32)slot, 4, &daddr, dport);

    ctx->user_ip4  = intercept_slot_addr((__u32)slot);
    ctx->user_port = (__u32)bpf_htons(cfg->listen_port);
    return 1;
}

SEC("cgroup/connect6")
int intercept_connect6(struct bpf_sock_addr *ctx)
{
    struct intercept_config_t *cfg = NULL;
    __u8 addr[16] = {};
    __u16 dport = bpf_ntohs((__u16)ctx->user_port);
    __u8  family = 6;
    int slot = 0;

    if (intercept_block_quic(ctx, dport))
        return 0;

    /* ::1, and the IPv4 loopback seen through a v4 mapped address */
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0) {
        if (ctx->user_ip6[2] == 0 && bpf_ntohl(ctx->user_ip6[3]) == 1)
            return 1;
        if (ctx->user_ip6[2] == bpf_htonl(0x0000ffffu)) {
            if ((bpf_ntohl(ctx->user_ip6[3]) >> 24) == 127)
                return 1;
            /* A v4 mapped destination is an IPv4 connection wearing an IPv6
             * socket: park it as IPv4 so the tunnel dials it as such. */
            family = 4;
        }
    }

    cfg = intercept_wanted(ctx, dport);
    if (!cfg)
        return 1;

    slot = intercept_take_slot();
    if (slot < 0)
        return 1;

    if (family == 4) {
        __u32 v4 = ctx->user_ip6[3];
        intercept_park_dst((__u32)slot, 4, &v4, dport);
    } else {
        /* Word by word rather than with a memcpy: the context is only
         * readable through loads of the width the verifier declared, and a
         * 16 byte copy is lowered to byte loads it refuses */
        __u32 words[4];

        words[0] = ctx->user_ip6[0];
        words[1] = ctx->user_ip6[1];
        words[2] = ctx->user_ip6[2];
        words[3] = ctx->user_ip6[3];
        __builtin_memcpy(addr, words, sizeof(addr));
        intercept_park_dst((__u32)slot, 6, addr, dport);
    }

    /* Redirected through a v4 mapped loopback address: the slot encoding needs
     * the 16 million addresses of 127.0.0.0/8, and IPv6 has a single loopback
     * address to offer. The socket stays AF_INET6 and the kernel routes it
     * over the IPv4 path, which is why a socket pinned with IPV6_V6ONLY cannot
     * be intercepted.
     *
     * Through a volatile view of the context: left to itself the compiler
     * fuses these adjacent stores into one base pointer (ctx + 12), and the
     * stricter verifiers reject a store through a ctx pointer carrying an
     * offset. The address checks above leave a ctx+12 pointer in a
     * callee-saved register that survives the calls, and the compiler reuses
     * it for the stores. A fresh copy of the context forces each store to use
     * ctx + its own constant offset, which the verifier accepts. */
    struct bpf_sock_addr *wc = ctx;
    asm volatile("" : "+r"(wc));
    wc->user_ip6[0] = 0;
    wc->user_ip6[1] = 0;
    wc->user_ip6[2] = bpf_htonl(0x0000ffffu);
    wc->user_ip6[3] = intercept_slot_addr((__u32)slot);
    wc->user_port   = (__u32)bpf_htons(cfg->listen_port);
    return 1;
}

/* getpeername(2) on a redirected socket would report the loopback slot: hand
 * back the address the process believes it is talking to, so that a client
 * checking its own peer — or logging it — sees no difference. */
SEC("cgroup/getpeername4")
int intercept_getpeername4(struct bpf_sock_addr *ctx)
{
    struct intercept_config_t *cfg = get_intercept_config();
    struct intercept_conn_t *entry = NULL;
    __u32 host_addr = bpf_ntohl(ctx->user_ip4);
    __u32 slot = 0, original = 0;

    if (!cfg || !cfg->enabled)
        return 1;

    if ((host_addr >> 24) != 127)
        return 1;

    if ((host_addr & 0x00ffffffu) < INTERCEPT_SLOT_BASE)
        return 1;

    slot = (host_addr & 0x00ffffffu) - INTERCEPT_SLOT_BASE;
    if (slot >= INTERCEPT_MAX_SLOTS)
        return 1;

    /* Another process may legitimately be talking to a loopback address that
     * happens to look like a slot: only the traced one is lied to */
    if (!is_target_program())
        return 1;

    entry = bpf_map_lookup_elem(&orig_dst_map, &slot);
    if (!entry || !entry->in_use || entry->family != 4)
        return 1;

    /* Copied through a local variable: the context is only writable with
     * stores of the exact width the verifier expects */
    __builtin_memcpy(&original, entry->daddr, 4);
    ctx->user_ip4  = original;
    ctx->user_port = (__u32)bpf_htons(entry->dport);
    return 1;
}

/* ------------------- TLS key capture (string-anchored keylog) ------------------ */

/* Session secrets for the TLS splice (include/tls_splice.h). One record per
 * secret, a handful per handshake: a small ring is plenty. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tls_secret_rb SEC(".maps");

/* The keylog function of the TLS library, found by tracers/tls_anchor.c from
 * the NSS labels it is called with — it is never exported:
 *   OpenSSL:   int  ssl_log_secret(SSL *s, const char *label,
 *                                  const uint8_t *secret, size_t secret_len)
 *   BoringSSL: bool ssl_log_secret(const SSL *ssl, const char *label,
 *                                  Span<const uint8_t> secret)
 * A Span is passed by value in two registers, data then size, so both put the
 * secret in the third and fourth argument. The probe sits on the entry, before
 * the library checks whether a keylog callback is installed: the process does
 * not have to be configured for anything. */
static __always_inline int submit_keylog(const void *ssl, const void *label,
                                         const void *secret, __u64 secret_len)
{
    struct tls_secret_event_t *ev = NULL;
    __u32 pid = 0;

    pid = is_target_program();
    if (!pid)
        return 0;

    /* 32 or 48 bytes in practice; refusing 64 lets the mask below give the
     * verifier a bound that fits the buffer */
    if (!label || !secret || secret_len == 0 || secret_len >= TLS_KEYS_SECRET_LEN)
        return 0;
    __u32 n = (__u32)secret_len;
    barrier_var(n);
    n &= (TLS_KEYS_SECRET_LEN - 1);

    ev = bpf_ringbuf_reserve(&tls_secret_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns      = bpf_ktime_get_ns();
    ev->pid               = pid;
    ev->tid               = (__u32)bpf_get_current_pid_tgid();
    ev->ssl_ptr           = (__u64)ssl;
    ev->source            = KEYSRC_ANCHOR;
    ev->label             = TLS_LBL_UNKNOWN;   /* named in label_name */
    ev->has_client_random = 0;                  /* resolved by trial decryption */
    ev->secret_len        = (__u8)secret_len;
    __builtin_memset(ev->client_random, 0, sizeof(ev->client_random));
    __builtin_memset(ev->secret, 0, sizeof(ev->secret));

    if (bpf_probe_read_user_str(ev->label_name, sizeof(ev->label_name), label) <= 0 ||
        bpf_probe_read_user(ev->secret, n, secret) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe")
int probe_tls_keylog(struct pt_regs *ctx)
{
    return submit_keylog((const void *)PT_REGS_PARM1(ctx), (const void *)PT_REGS_PARM2(ctx),
                         (const void *)PT_REGS_PARM3(ctx), (__u64)PT_REGS_PARM4(ctx));
}

/* OpenSSL with ssl_log_secret() inlined into its callers (Ubuntu 22.04's
 * 3.0.2): the anchor is the function it wraps,
 *   static int nss_keylog_int(const char *prefix, SSL *ssl,
 *                             const uint8_t *parameter_1, size_t parameter_1_len,
 *                             const uint8_t *parameter_2, size_t parameter_2_len)
 * called with the client random first and the secret second. */
SEC("uprobe")
int probe_tls_keylog_nss(struct pt_regs *ctx)
{
    return submit_keylog((const void *)PT_REGS_PARM2(ctx), (const void *)PT_REGS_PARM1(ctx),
                         (const void *)PT_REGS_PARM5(ctx), (__u64)PT_REGS_PARM6(ctx));
}

/* HMAC key setup, for TLS stacks with no keylog function to probe (rustls on
 * ring, a static OpenSSL built without one). Every TLS 1.3 secret becomes an
 * HMAC key, and HMAC's first compressed block is that key XOR 0x36 padded with
 * 0x36: on the SHA-2 block function, a single such block hands the secret
 * over. Wrong guesses cost nothing, trial decryption discards them.
 *   void block_data_order(uint32_t/uint64_t *state, const uint8_t *data, size_t nblocks) */
static __always_inline int hmac_key_setup(struct pt_regs *ctx, __u32 block, __u32 key_len)
{
    struct tls_secret_event_t *ev = NULL;
    __u8 buf[128];
    __u8 any = 0;
    __u32 pid = 0, i = 0;

    if (PT_REGS_PARM3(ctx) != 1)
        return 0;
    pid = is_target_program();
    if (!pid)
        return 0;
    if (bpf_probe_read_user(buf, block, (const void *)PT_REGS_PARM2(ctx)) < 0)
        return 0;
    for (i = key_len; i < block && i < sizeof(buf); i++)
        if (buf[i] != 0x36)
            return 0;
    for (i = 0; i < key_len && i < sizeof(buf); i++)
        any |= buf[i] ^ 0x36;
    if (!any)
        return 0;   /* the all-zero key of an HKDF-Extract without salt */

    ev = bpf_ringbuf_reserve(&tls_secret_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid;
    ev->tid          = (__u32)bpf_get_current_pid_tgid();
    ev->source       = KEYSRC_HMAC;
    ev->label        = TLS_LBL_UNKNOWN;
    ev->secret_len   = (__u8)key_len;
    for (i = 0; i < key_len && i < TLS_KEYS_SECRET_LEN; i++)
        ev->secret[i] = buf[i] ^ 0x36;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe")
int probe_hmac_sha256(struct pt_regs *ctx)
{
    return hmac_key_setup(ctx, 64, 32);    /* SHA-256 suites: 32-byte secrets */
}

SEC("uprobe")
int probe_hmac_sha512(struct pt_regs *ctx)
{
    return hmac_key_setup(ctx, 128, 48);   /* SHA-384 suites: 48-byte secrets */
}

/* A followed process executing another program brings a TLS stack the key
 * probe is not on yet (a launcher script, an updater, the real binary): its
 * pid goes to userspace, which probes the new executable before it connects.
 * "Before" is enforced: the process is stopped here, before it runs a single
 * instruction of the new program, and continued once the probe is in place —
 * a command line client handshakes within milliseconds of starting. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);
} exec_rb SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx)
{
    __u32 pid = is_target_program();
    __u32 *ev = NULL;

    if (!pid)
        return 0;
    ev = bpf_ringbuf_reserve(&exec_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;
    *ev = pid;
    bpf_ringbuf_submit(ev, 0);
    /* userspace sends SIGCONT for every pid it was told about */
    bpf_send_signal(19 /* SIGSTOP */);
    return 0;
}

/* The same for a library loaded at run time (a Node addon such as Discord's
 * updater.node, Flutter's engine): on dlopen's return it is mapped, and its
 * code has not been called yet. */
SEC("uretprobe")
int trace_dlopen(struct pt_regs *ctx)
{
    __u32 pid = is_target_program();
    __u32 *ev = NULL;

    if (!pid || !PT_REGS_RC(ctx))
        return 0;
    ev = bpf_ringbuf_reserve(&exec_rb, sizeof(*ev), 0);
    if (!ev)
        return 0;
    *ev = pid;
    bpf_ringbuf_submit(ev, 0);
    bpf_send_signal(19 /* SIGSTOP */);
    return 0;
}

char _license[] SEC("license") = "GPL";

