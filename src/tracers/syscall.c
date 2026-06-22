#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>


static struct ring_buffer *ring_buf = NULL;

/**
 * decode_syscall
 *
 * Description:
 * This function is responsible to parse correctly unsigned long syscall arguments based on the correct syscall number.
 *
 * Params:
 * const long syscall_number: system call identifier
 * const unsigned long args[6]: system call arguemnts, up to a maximum of 6.
 *
 * */
void decode_syscall(const __u64 syscall_number, const void *args[6])
{
	switch (syscall_number) {
		case 0:
			/* SYS_READ */
			printf("sys_read (%lu, %p, %lx)\n",  args[0], args[1], args[2]);
			break;
		case 1:
			/* SYS_WRITE */
			printf("sys_write (%lu, %p, %lx)\n",  args[0], args[1], args[2]);
			break;
		case 2:
			/* SYS_OPEN */
			printf("sys_open (%p, %d, %d)\n",  args[0], args[1], args[2]);
			break;
		case 3:
			/* SYS_CLOSE */
			printf("sys_close (%lu)\n",  args[0]);
			break;
		case 4:
			/* SYS_STAT */
			printf("sys_stat (%p, %p)\n",  args[0], args[1]);
			break;
		case 5:
			/* SYS_FSTAT */
			printf("sys_fstat (%lu, %p)\n",  args[0], args[1]);
			break;
		case 6:
			/* SYS_LSTAT */
			printf("sys_lstat (%p, %p)\n",  args[0], args[1]);
			break;
		case 7:
			/* SYS_POLL */
			printf("sys_poll (%p, %lu, %ld)\n",  args[0], args[1], args[2]);
			break;
		case 8:
			/* SYS_LSEEK */
			printf("sys_lseek (%u, %lx, %u)\n", args[0], args[1], args[2]);
			break;
		case 9:
			/* SYS_MMAP */
			printf("sys_mmap (%lu, %lu, %lu, %lu, %lu, %lu)\n", args[0], args[1], args[2], args[3], args[4], args[5]);
			break;
		case 10:
			/* SYS_MPROTECT */
			printf("sys_mprotect (%lu, %lx, %lu)\n", args[0], args[1], args[2]);
			break;	
		case 11:
			/* SYS_MUNMAP */
			printf("sys_munmap (%lu, %lx)\n", args[0], args[1]);
			break;	
		case 12:
			/* SYS_BRK */
			printf("sys_brk (%lu)\n", args[0]);
			break;	
		case 13:
			/* SYS_RT_SIGACTION */
			printf("sys_rt_sigaction (%d, %p, %p, %lx)\n", args[0], args[1], args[2], args[3]);
			break;
		case 14:
			/* SYS_RT_PROCMASK */
			printf("sys_rt_sigaction (%d, %p, %p, %lx)\n", args[0], args[1], args[2], args[3]);
			break;
		case 15:
			/* SYS_RT_SIGRETURN */
			printf("sys_rt_sigreturn (%lu)\n", args[0]);
			break;
		case 16:
			/* SYS_IOCTL */
			printf("sys_ioctl (%lu, %lu, %lu)\n", args[0], args[1], args[2]);
			break;
		case 17:
			/* SYS_PREAD64 */
			printf("sys_pread64 (%lu, %p, %lx, %lx)\n", args[0], args[1], args[2], args[3]);
			break;
		case 18:
			/* SYS_PWRITE64 */
			printf("sys_write64 (%lu, %p, %lx, %lx)\n", args[0], args[1], args[2], args[3]);
			break;
		case 19:
			/* SYS_READV */
			printf("sys_readv (%lu, %p, %zu, %lu)\n", args[0], args[1], args[2]);
			break;
		case 20:
			/* SYS_WRITEV */
			printf("sys_writev (%lu, %p, %zu, %lu)\n", args[0], args[1], args[2]);
			break;
		case 21:
			/* SYS_ACCESS */
			printf("sys_access (%lx, %d)\n", args[0], args[1]);
			break;
		case 22:
			/* SYS_PIPE */
			printf("sys_pipe (%p)\n", args[0]);
			break;
		case 23:
			/* SYS_SELECT */
			printf("sys_select (%d, %p, %p, %p, %p)\n", args[0], args[1], args[2], args[3], args[4]);
			break;
		case 24:
			/* SYS_SCHED_YIELD */
			printf("sys_sched_yield\n\n");
			break;
		case 25:
			/* SYS_MREMAP */
			printf("sys_mremap (%lu, %lu, %lu, %lu, %lu)\n", args[0], args[1], args[2], args[3], args[4]);
			break;
		case 26:
			/* SYS_MYSNC */
			printf("sys_mysnc	(%lu, %lx, %d)\n", args[0], args[1], args[2]);
			break;
		case 27:
			/* SYS_MINCORE */
			printf("sys_mincore (%lu, %lx, %p)\n", args[0], args[1], args[2]);
			break;
		case 28:
			/* SYS_MADVISE */
			printf("sys_madvise (%lu, %lx, %d)\n", args[0], args[1], args[2]);
			break;
		case 29:
			/* SYS_SHMGET */
			printf("sys_shmget (%lx, %lx, %d)\n", args[0], args[1], args[2]);
			break;
		case 30:
			/* SYS_SHMAT */
			printf("sys_shmat	(%d, %p, %d)\n", args[0], args[1], args[2]);
			break;
		// case 262:
		// 	/* SYS_NEWFSTATAT */
		// 	printf("sys_newfstatat\n\n");
		// 	printf("args: 		(%d, %p, %p)\n", args[0], args[1], args[2]);
		// 	break;
		default:
			// printf("Failed to parse syscall number: %lx", syscall_number);
			printf("syscall (%lx, %lx, %lx, %lx, %lx, %lx)\n", args[0], args[1], args[2], args[3], args[4], args[5]);
			break;
	}
}

/*
 * syscall_event_handler 
 * 
 * Description:
 * This syscall event handler performs dumping of process system calls. 
 * Based on how ePtracer has been configured, output will be redirected into stdout or 
 * external logging file. 
 * 
 * Params:
 * void *ctx: perf event's context.
 * void *data: syscall event containing process, thread and arguments.
 * __u32 size: syscall event size.
 *
 * */
static int syscall_event_handler(void *ctx, void *data, size_t size)
{
	struct timespec t_spec;
    clock_gettime(CLOCK_REALTIME, &t_spec);
    
    long microseconds = t_spec.tv_sec * 1000000 + t_spec.tv_nsec / 1000;
	char metric [1024];
    struct syscall_event_t *ev = (struct syscall_event_t *)data;

    switch(ev->type) {
        case EVENT_PTRACE:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"ptrace\", request=\"%d\", pid=\"%d\", addr=\"%p\", data=\"%p\"} %ld", 
                     ev->pid, (int)ev->args[0], (int)ev->args[1], (void*)ev->args[2], (void*)ev->args[3], microseconds);
            break;
        case EVENT_READ:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"read\", fd=\"%d\", buf=\"%p\", count=\"%lu\"} %ld", 
                     ev->pid, (int)ev->args[0], (void*)ev->args[1], (unsigned long)ev->args[2], microseconds);
            break;
        case EVENT_EXECVE:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"execve\", filename=\"%s\", argv=\"%p\", envp=\"%p\"} %ld", 
                     ev->pid, ev->str1, (void*)ev->args[1], (void*)ev->args[2], microseconds);
            break;
        case EVENT_FORK:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"fork\"} %ld", ev->pid, microseconds);
            break;
        case EVENT_CLONE:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"clone\", flags=\"%lx\", child_stack=\"%p\", parent_tid=\"%p\", child_tid=\"%p\"} %ld", 
                     ev->pid, ev->args[0], (void*)ev->args[1], (void*)ev->args[2], (void*)ev->args[3], microseconds);
            break;
        case EVENT_MPROTECT:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"mprotect\", addr=\"%p\", len=\"%lu\", prot=\"%d\"} %ld", 
                     ev->pid, (void*)ev->args[0], (unsigned long)ev->args[1], (int)ev->args[2], microseconds);
            break;
        case EVENT_OPENAT:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"openat\", fd=\"%d\", filename=\"%s\", flags=\"%d\", mode=\"%d\"} %ld", 
                     ev->pid, (int)ev->args[0], ev->str1, (int)ev->args[2], (int)ev->args[3], microseconds);
            break;
        case EVENT_MMAP:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"mmap\", addr=\"%p\", length=\"%lu\", prot=\"%d\", flags=\"%d\", fd=\"%d\", off=\"%lu\"} %ld", 
                     ev->pid, (void*)ev->args[0], (unsigned long)ev->args[1], (int)ev->args[2], (int)ev->args[3], (int)ev->args[4], (unsigned long)ev->args[5], microseconds);
            break;
        case EVENT_WRITE:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"write\", fd=\"%d\", buf=\"%p\", count=\"%lu\"} %ld", 
                     ev->pid, (int)ev->args[0], (void*)ev->args[1], (unsigned long)ev->args[2], microseconds);
            break;
        case EVENT_CHOWN:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"chown\", filename=\"%s\", uid=\"%d\", gid=\"%d\"} %ld", 
                     ev->pid, ev->str1, (int)ev->args[1], (int)ev->args[2], microseconds);
            break;
        case EVENT_MOUNT:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"mount\", source=\"%s\", target=\"%s\", fstype=\"%s\", flags=\"%lx\", data=\"%p\"} %ld", 
                     ev->pid, ev->str1, ev->str2, ev->str3, (unsigned long)ev->args[3], (void*)ev->args[4], microseconds);
            break;
        case EVENT_UMOUNT:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"umount\", target=\"%s\", flags=\"%d\"} %ld", 
                     ev->pid, ev->str1, (int)ev->args[1], microseconds);
            break;
        case EVENT_IOCTL:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"binder_ioctl\", fd=\"%d\", cmd=\"%lu\", arg=\"%lu\"} %ld", 
                     ev->pid, (int)ev->args[0], (unsigned long)ev->args[1], (unsigned long)ev->args[2], microseconds);
            break;
        case EVENT_SETUID:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"setuid\", uid=\"%d\"} %ld", ev->pid, (int)ev->args[0], microseconds);
            break;
        case EVENT_SETGID:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"setgid\", gid=\"%d\"} %ld", ev->pid, (int)ev->args[0], microseconds);
            break;
        case EVENT_CAPSET:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"capset\", hdr=\"%p\", data=\"%p\"} %ld", 
                     ev->pid, (void*)ev->args[0], (void*)ev->args[1], microseconds);
            break;
        case EVENT_PRCTL:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"prctl\", option=\"%d\", arg2=\"%lu\", arg3=\"%lu\", arg4=\"%lu\", arg5=\"%lu\"} %ld", 
                     ev->pid, (int)ev->args[0], (unsigned long)ev->args[1], (unsigned long)ev->args[2], (unsigned long)ev->args[3], (unsigned long)ev->args[4], microseconds);
            break;
        case EVENT_KEYCTL:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"keyctl\", cmd=\"%d\", arg2=\"%lu\", arg3=\"%lu\", arg4=\"%lu\", arg5=\"%lu\"} %ld", 
                     ev->pid, (int)ev->args[0], (unsigned long)ev->args[1], (unsigned long)ev->args[2], (unsigned long)ev->args[3], (unsigned long)ev->args[4], microseconds);
            break;
        default:
            snprintf(metric, sizeof(metric), "eptracer{pid=\"%d\", syscall=\"unknown\"} %ld", ev->pid, microseconds);
            break;
    }
	printf("%s\n", metric);
	return 0;
}

void* syscall_tracer(void *syscall_tracer_arguments)
{
	int ret = 0;
    struct eptracer_bpf *skel;
  
    skel = ((struct syscall_tracer_args*) syscall_tracer_arguments)->skel;

	log_debug("[+] Creating a BPF ring buffer manager...\n");
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.syscall_rb_map), syscall_event_handler, NULL, NULL);
	if (!ring_buf) {
		log_error("[!] Error creating ring buffer manager\n");
		// cleanup();
        exit(0);
	}
	log_debug("[+] Ring buffer successfully created\n");

	log_debug("[+] Polling events from ring buffer...\n");
	while ((ret = ring_buffer__poll(ring_buf, 100)) >= 0) {}
	return NULL;
}
