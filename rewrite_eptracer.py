import re

with open("src/eptracer.bpf.c", "r") as f:
    content = f.read()

# We need to find all SEC("tracepoint/syscalls/sys_enter_*") blocks.
# The structure is:
# SEC("tracepoint/syscalls/sys_enter_XXX")
# int XXX_decode(struct trace_event_raw_sys_enter *ctx) 
# { ... }

# We'll replace them all with a single multiplexer.
# First, let's extract the body of each to see what they do.
# Actually, they are very simple. They mostly reserve a ringbuf, set type, copy args, and submit.
# I will just write a new file completely.

new_code = """
// ... (I will append the original headers and maps) ...
"""

# I will parse the original file up to the first SEC("tracepoint/syscalls/")
idx = content.find('SEC("tracepoint/syscalls/sys_enter_ptrace")')
header_part = content[:idx]

# Remove the old SEC("perf_event") get_stacktrace? No, keep it!
# Wait, get_stacktrace is SEC("perf_event") and is before sys_enter_ptrace.

multiplexer = """
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
            bpf_printk("open(filename=\\"%s\\", flags=\\"%lu\\", mode=\\"%lu\\")", "", flags, mode);
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

char _license[] SEC("license") = "GPL";
"""

with open("src/eptracer.bpf.c", "w") as f:
    f.write(header_part)
    f.write(multiplexer)

