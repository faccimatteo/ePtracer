#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "include/args.h"
#include "include/bpf/blazesym.h"
#include "include/log.h"
#include "include/bpf/eptracer.skel.h"
#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"

extern int errno;
static struct arguments args;
static int log_level = LOG_DEBUG;
static FILE *f = NULL;
static struct blaze_symbolizer *symbolizer = NULL;
static struct eptracer_bpf *skel = NULL;
static struct perf_buffer *perf_buf = NULL;
static struct ring_buffer *ring_buf = NULL;


/* structure to send argument to stack_tracer thread */
struct stack_tracer_args 
{
	bool *online_mask;
	int num_cpus;
	int num_online_cpus;
};

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/**
 * cleanup
 *
 * Description:
 * cleanup resources if something goes wrong or SIGTERM has been captured (future impl.)
 *
 * */
void cleanup() 
{
	if (skel) {
		eptracer_bpf__destroy(skel);        
		skel = NULL;
    }
	if (symbolizer) {
		blaze_symbolizer_free(symbolizer);
		symbolizer = NULL;
    }
	if (perf_buf) {
		perf_buffer__free(perf_buf);
		perf_buf = NULL;
    }
}
	

/*
 * libbpf_printf_fn
 *
 * Description:
 * Callback function invoked every time a log event is produced by libbpf.
 *
 * Params:
 * enum libbpf_print_level level: logging level used by libbpf. 
 * Checks https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.h#L90 for more details. 
 * const char *format: format needed to libbpf to produce our logs. 
 * va_list fn_args: arguments needed to libbpf to produce our logs.
 *
 * Return:
 * Number of bytes written to log file descriptor if verbose mode is activated, -1 otherwise.
 * */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list fn_args)
{

	/* Logs non-debug info if verbose is not requested */
	if (level > LIBBPF_INFO) {
		return 0;
	}

	if (args.log_file && strlen(args.log_file) != 0) {
        return fprintf(f, format, fn_args);
	} else {
		return fprintf(stdout, format, fn_args);
	}
	return -1;
}

/*
 * get_process_identifier
 *
 * Description:
 * Defines the process identifier that will be traced.  
 *
 * Return:
 * Always use PID first.                      
 * Otherwise if cannot use PID, use process name.                         
 * Return NULL if no PID nor process name are defined.
 * 
 * */
static char* get_process_identifier()
{	
	struct arguments *program_arguments = &args;
	if (!program_arguments){
		log_error("[!] Unexpected null program arguments.\n");
		return NULL;
	}
	if (program_arguments->process_pid && strlen(program_arguments->process_pid) != 0)
		return program_arguments->process_pid;
	if (program_arguments->process_name && strlen(program_arguments->process_name) != 0)
		return program_arguments->process_name;
	return NULL;
}

/* 
 * initialize_array  
 * 
 * Description:
 * Initializes the programs to trace.
 *
 * Params:
 * int fd: bpf map file descriptor for the current eptracer process.
 * char *process_identifier: process identifier obtained from get_process_identifier. 
 * This can be a PID or a name of a process. Note that process name might not correspond
 * to process name listed from `ps -aux`. Said so, consider prefer PID over process name
 * as program identifier.
 *
 * Return:
 * 0 on success, or a negative error in case of failure. 
 * For more details about bpf_map_update_elem error checks 
 * https://man7.org/linux/man-pages/man7/bpf-helpers.7.html#bpf_map_update_elem 
 *
 * PLANNED CHANGES:
 * By now, only one program is passed from program arguments.
 * Instead, the idea is to pass a list of process_identifier with a number of program 
 * to trace < MAX_PROGRAM_TO_TRACE.
 *
 * */
static int initialize_array(int fd, char *process_identifier)
{
	char name[MAX_PROGRAM_STRING_LEN];
	int bpf_error = 0;
	__u32 i = 0;

	if (strlen(process_identifier) > MAX_PROGRAM_STRING_LEN) {
		log_error("[!] Specified program identifier exceeds program max length.\n");
		return -1;
	}

	strncpy(name, process_identifier, MAX_PROGRAM_STRING_LEN);
    log_debug("[+] Starting tracing program: %s", name);

	/* Setting process to trace for all the CPUs */
    bpf_error = bpf_map_update_elem(fd, &i, &name, BPF_ANY);
	if (bpf_error < 0)
		log_error("[!] Failed to update BPF map with program name %s: error %d", name, bpf_error);

	return bpf_error;
}

/**
 * load_BPF_program
 *
 * Description:
 * Loads BPF program in kernel. 
 * Use already present one if already loaded.
 *
 * Return:
 * Skeleton associated to BPF program.
 *
 * */
static struct eptracer_bpf* load_BPF_program() 
{
	log_debug("[+] Loading BPF program into kernel...\n");
	if (!skel) {
		skel = eptracer_bpf__open_and_load();
	} else {
		log_debug("[+] Using already loaded BPF program\n");
	}
	return skel;	
}

/*
 * print_frame
 *
 * Description:
 * Prints user or kernel stack frame single reference.
 *
 * Params:
 * const char *name: function's name.
 * uintptr_t input_addr: 
 * uintptr_t addr: 
 * uint64_t offset: offset from stack base address.
 * const blaze_symbolize_code_info* code_info: information obtained from blaze related 
 * to the stack address.
 */
static void print_frame(
	const char *name, 
	uintptr_t input_addr,
	uintptr_t addr,
	uint64_t offset,
	const blaze_symbolize_code_info* code_info
)
{
    /* If an input address is specified, we have a new symbol we can print. */
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx\n", input_addr, name, addr, offset);
		/* Log stack tracing information if */
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
    } else {
		printf("%16s  %s\n", "", name);

		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			printf("[inlined]\n");
		}
    }
}

/*
 * show_stack_trace
 *
 * Description:
 * Recover information from stack addresses and output formatted symbolic stack frames.
 *
 * Params:
 * __u64 *stack: stack pointer used to recover stack data.
 * int stack_sz: stack size.
 * pid_t pid: process id. 
 *
 * */
static void show_stack_trace(const __u64 *stack, unsigned long stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *result;
	const struct blaze_sym *sym;
	unsigned long i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = (uint) pid,
		};
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}


	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
		  inlined = &sym->inlined[j];
		  print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(result);
}

/*
 * stack_event_handler
 *
 * Description:
 * This "perf event" event handler extract stack frames (kernel and user) from kernel 
 * perf event and performs kernel and userspace stack tracing. 
 * Based on how ePtracer has been configured, output will be redirected into stdout or 
 * external logging file. 
 * 
 * Params:
 * void *ctx: perf event's context.
 * int cpu: cpu id processing the event.
 * void *stack_data: pid stack information containing addresses and size.
 * __u32 stack_size: stack size.
 *
 * */
static void stack_event_handler(void *ctx, int cpu, void *stack_data, __u32 stack_size)
{
	const struct stack_trace_t *e = stack_data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int fd = 0;

	/* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.\n");
	}
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("--------------------------------------------------------------\n");
	printf("[+] Stack trace\n");
	printf("Time ->  %-8s\n", ts);
	printf("PID -> %d\n", e->pid);
	printf("CPU -> %d\n", cpu);
	
	/* Showing kernel stack events if any */
	if (e->kern_stack_size > 0) {
	    printf("Kernel stack size -> %d", e->kern_stack_size);
		printf("Kernel:\n");
		show_stack_trace(e->kern_stack, e->kern_stack_size / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	/* Showing user stack events if any */
	if (e->user_stack_size > 0) {
		printf("Userspace:\n");
	    printf("User stack size -> %d\n", e->user_stack_size);
		show_stack_trace(e->user_stack, e->user_stack_size / sizeof(__u64), e->pid);
	} else {
		printf("No Userspace Stack\n");
	}
	printf("--------------------------------------------------------------\n");
	/* Keep events spaced by one line */
	printf("\n");

}

void *stack_tracer(void *stack_tracer_arguments);

void *stack_tracer(void *stack_tracer_arguments)
{
	bool *online_mask = NULL;
	int num_online_cpus = 0;
	int ret = 0, num_cpus = 0;
	int pid = -1, cpu = 0, i = 0;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	int *perfds = NULL;
    long perfd;

	/* Getting necessary params */
	online_mask = ((struct stack_tracer_args*) stack_tracer_arguments)->online_mask;
	num_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_cpus;
	num_online_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_online_cpus;

	/* Setting up performance monitoring for cpus */
	perfds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		perfds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));
	
	memset(&attr, 0, sizeof(attr));
	//attr.type = PERF_TYPE_HARDWARE;
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	// attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_freq = 10000;
	attr.freq = 1;
	/* Configuring perf event sample type */
	attr.sample_type = PERF_SAMPLE_STACK_USER | PERF_SAMPLE_CALLCHAIN;


	/* Setting up performance monitoring for cpus */
	for (cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;
		
		/* Set up performance monitoring on a CPU/Core */
		perfd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (perfd < 0) {
			log_error("[!] Fail to set up performance monitor on a CPU/Core\n");
			cleanup();
		}
		perfds[cpu] = perfd;

		/* Assign each CPU a BPF program to analyze stack traces */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.get_stacktrace, perfd);
		if (!links[cpu]) {
			cleanup();
		}
	}

	
	// PERF EVENT INITIALIZATION PART

	log_debug("[+] Creating blaze symbolizer...\n");
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		log_error("Fail to create a symbolizer\n");
		cleanup();
	}
	log_debug("[+] Successfully created blaze symbolizer\n");

	log_debug("[+] Creating a BPF perfbuffer manager...\n");
	perf_buf = perf_buffer__new(bpf_map__fd(skel->maps.perfmap), 8, stack_event_handler, NULL, NULL, NULL);
	if (!perf_buf) {
		log_error("[!] Error creating perf buffer manager\n");
		cleanup();
	}
	log_debug("[+] Ring buffer successfully created\n");

	log_debug("[+] Polling events from perf buffer...\n");
	while ((ret = perf_buffer__poll(perf_buf, 100)) >= 0) {}
	return NULL;
}

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
	const struct raw_syscall_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int fd = 0;

	/* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.\n");
		return 1;
	}
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("Time ->  %-8s\n", ts);
	printf("Syscall ID -> %ld\n", e->syscall_id);
	printf("PID -> %lu\n", e->pid);
	printf("TGID -> %lu\n", e->tgid);
	decode_syscall(e->syscall_id, e->args);
	printf("--------------------------------------------------------------\n");
	return 0;
}

void *syscall_tracer();

void* syscall_tracer()
{
	int ret = 0;

	log_debug("[+] Creating a BPF ring buffer manager...\n");
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.syscall_rb_map), syscall_event_handler, NULL, NULL);
	if (!ring_buf) {
		log_error("[!] Error creating ring buffer manager\n");
		cleanup();
	}
	log_debug("[+] Ring buffer successfully created\n");

	log_debug("[+] Polling events from ring buffer...\n");
	while ((ret = ring_buffer__poll(ring_buf, 100)) >= 0) {}
	return NULL;
}

int main(int argc, char **argv) 
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	bool *online_mask = NULL;
	int err = 0, num_cpus = 0, num_online_cpus = 0, i = 0, thread_index = 0;
	struct stack_tracer_args stack_thread_arguments;
	char *process_id = NULL;
	pthread_t threads[2];
	pthread_t stack_tracer_thread;
	pthread_t syscall_tracer_thread;

	args.log_file = "";
	args.process_pid = "";
	args.process_name = "";
	args.show_stacktrace = false;
	args.show_syscall = false;
	args.verbose = false;
	
	/* Getting number of online cpus */
	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		log_error("[!] Failed to parse cpus number\n");
		return 1;	
	}

	/* Getting number of usable cpus */
	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		log_error("[!] Fail to get the number of processors\n");
		return 1;
	}
	
	/* Parsing command line arguments */
	err = argp_parse(&argp, argc, argv, 0, 0, &args);
	if (err) {
		log_error("[!] Error parsing program arguments\n");
		return 1;
	}

	/* Logging to file if requested */
	if (strlen(args.log_file) != 0) {
		f = fopen(args.log_file, "w+\n");
		if (!f) {
			log_error("[!] Failed to create logging file\n");
			return 1;	
		} else {
			if (log_add_fp(f, log_level) < 0) {
				log_error("[!] Failed to add logging file\n");
				return 1;
			} else {
				log_debug("[+] Successfully added logging file %s", args.log_file);
			}
		}
	}
	
	/* Handling libbpf errors and debug info callback */
	if (args.log_file && strlen(args.log_file) != 0) {
		printf("[+] Logging ePtracer into: %s", args.log_file);
	}
	if (libbpf_set_print(libbpf_print_fn) < 0) {
		printf("[!] Failed to initialize ePtracer in logging mode.\n");
	};
	
	/* Get BPF skeleton to manage BPF objects in a easier way */
	skel = load_BPF_program();
	if (!skel) {
			log_error("[!] Error opening and loading BPF file\n");
			cleanup();
			return 1;
	}		
	log_debug("[+] BFP program correctly loaded\n");

	log_debug("[+] Setting user process to trace...\n");
	process_id = get_process_identifier();
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0) {
		log_error("[!] Error setting process to trace. Please make sure to specify one process to trace using PID or name identifier.\n");
		cleanup();
		return 1;
	}
	log_debug("[+] Successfully tracing process %s", process_id);

	log_debug("[+] Attaching to BPF program...\n");
	errno = eptracer_bpf__attach(skel);
	if (errno) { 
		log_error( "[!] Error finding BPF program\n");
		cleanup();
	}

	log_debug("[+] Successfully attached to BFP program\n");
	if (strncmp(args.process_pid, "", 1) != 0) {
		log_debug("[+] PID: %s", args.process_pid);
	}
	if (strncmp(args.process_name, "", 1) != 0) {
		log_debug("[+] Process Name: %s", args.process_name);
	}
	log_debug("[+] Verbose: %d", args.verbose);
	if (strncmp(args.log_file, "", 1) != 0) {
		log_debug("[+] Log file: %s", args.log_file);
	} else {
		log_debug("[+] No logging file specified, logging into stdout\n");
	}
	stack_thread_arguments.online_mask = online_mask;
	stack_thread_arguments.num_cpus = num_cpus;
	stack_thread_arguments.num_online_cpus = num_online_cpus;
	
	if (args.show_stacktrace) {
		/* Creating thread that will handle communication with stack tracer BPF program */	
		if (pthread_create(&stack_tracer_thread, NULL, stack_tracer, (void*) &stack_thread_arguments)) {
			log_error("[!] Failed to create stack tracer thread.\n");
			cleanup();
			return 1;
		}
		threads[thread_index++] = stack_tracer_thread;
	}
	
	if (args.show_syscall) {
		/* Creating thread that will handle communication with syscall tracer BPF program */	
		if (pthread_create(&syscall_tracer_thread, NULL, syscall_tracer, NULL)) {
			log_error("[!] Failed to create syscall tracer thread.\n");
			cleanup();
			return 1;
		}
		threads[thread_index++] = syscall_tracer_thread;
	}

	if (!args.show_stacktrace && !args.show_syscall) {
		printf("[?] ePtracer is not tracing any event. To trace events, take a look at the usage using --help\n");
        return 0;
	}
  
	for (i = 0; i < thread_index; ++i) {
		pthread_join(threads[i], NULL);
	}
	
	return 0;
}
