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

#include "lib/args.h"
#include "lib/blazesym.h"
#include "lib/log.h"
#include "lib/bpf/eptracer.skeleton.h"
#include "lib/bpf/stack_tracing.h"
#include "lib/bpf/syscall_tracing.h"

extern int errno;
static struct arguments args;
static int log_level = LOG_DEBUG;
static FILE *f = NULL;
static struct blaze_symbolizer *symbolizer = NULL;
static struct eptracer_bpf *skel = NULL;
static struct perf_buffer *perf_buf = NULL;


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
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
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

	if (args.verbose) {
		if (args.log_file && strlen(args.log_file) != 0) {
			log_info("[+] Logging ePtracer in: %s", args.log_file);
			return fprintf(f, format, fn_args);
		} else {
			return fprintf(stdout, format, fn_args);
		}
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
		log_error("[!] Unexpected null program arguments.");
		return NULL;
	}
	if (program_arguments->process_pid && strlen(program_arguments->process_pid) != 0)
		return program_arguments ->process_pid;
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
	char bpf_error = 0;

	if (strlen(process_identifier) > MAX_PROGRAM_STRING_LEN) {
		log_error("[!] Specified program identifier exceeds program max length.");
		return -1;
	}

	strncpy(name, process_identifier, MAX_PROGRAM_STRING_LEN);
    log_debug("[+] Starting tracing program: %s", name);
	__u32 i = 0;

	/* Setting program to trace for all the CPUs */
    bpf_error = bpf_map_update_elem(fd, &i, &name, BPF_ANY);
	if (bpf_error < 0)
		log_error("[!] Failed to update BPF map with program name %s: error %d", name, bpf_error);

	return bpf_error;
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
		log_info("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		/* Log stack tracing information if */
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			log_info(" %s/%s:%u", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			log_info(" %s:%u", code_info->file, code_info->line);
		} else {
			log_info("");
		}
    } else {
		printf("%16s  %s", "", name);

		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			log_info("@ %s/%s:%u [inlined]", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			log_info("@ %s:%u [inlined]", code_info->file, code_info->line);
		} else {
			log_info("[inlined]");
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
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
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
			log_info("%016llx: <no-symbol>", stack[i]);
			continue;
		}

		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
		  inlined = &sym->inlined[j];
		  print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_result_free(result);
}

/*
 * handle_event
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
static void handle_event(void *ctx, int cpu, void *stack_data, __u32 stack_size)
{
	const struct stack_trace_t *e= stack_data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int fd = 0;

	/* Can't log with empty stacks */
	if (e->kern_stack_size <= 0 && e->user_stack_size <= 0)
		return;

	/* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.");
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	log_info("--------------------------------------------------------------");
	log_info("[+] Perf event");
	log_info("Time ->  %-8s", ts);
	log_info("PID -> %d", e->pid);
	log_info("Kernel stack size -> %d", e->kern_stack_size);
	log_info("User stack size -> %d", e->user_stack_size);
	
	/* Showing kernel stack events if any */
	if (e->kern_stack_size > 0) {
		log_info("Kernel:");
		show_stack_trace(e->kern_stack, e->kern_stack_size / sizeof(__u64), 0);
	} else {
		log_info("No Kernel Stack");
	}

	/* Showing user stack events if any */
	if (e->user_stack_size > 0) {
		log_info("Userspace:");
		show_stack_trace(e->user_stack, e->user_stack_size/ sizeof(__u64), e->pid);
	} else {
		log_info("No Userspace Stack");
	}
	log_info("--------------------------------------------------------------");
	/* Keep events spaced by one line */
	log_info("");

}

void *stack_tracer(void *stack_tracer_arguments);

void *stack_tracer(void *stack_tracer_arguments)
{
	bool *online_mask = NULL;
	int num_online_cpus = 0;
	int ret = 0, num_cpus = 0;
	int pid = -1, cpu = 0, i = 0;
	char* process_id = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	int *pefds = NULL, pefd;

	/* Getting necessary params */
	online_mask = ((struct stack_tracer_args*) stack_tracer_arguments)->online_mask;
	num_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_cpus;
	num_online_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_online_cpus;

	/* Setting up performance monitoring for cpus */
	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
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
	// Added for VM
	attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER;

	log_debug("[+] Loading BPF program into kernel...");
	skel = eptracer_bpf__open_and_load();
	if (!skel) {
		log_error("[!] Error opening and loading BPF file");
		goto cleanup;
	}
	log_debug("[+] BFP program correctly loaded");

	/* Setting up performance monitoring for cpus */
	for (cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;
		
		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			log_error("[!] Fail to set up performance monitor on a CPU/Core");
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
		if (!links[cpu]) {
			goto cleanup;
		}
	}

	log_debug("[+] Attaching to BPF program...");
	errno = eptracer_bpf__attach(skel);
	if (errno) { 
		log_error( "[!] Error finding BPF program");
		goto cleanup;
	}
	log_debug("[+] Successfully attached to BFP program");

	log_debug("[+] Setting user program to trace...");
	process_id = get_process_identifier();
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0) {
		log_error("[!] Error setting program to trace");
		goto cleanup;
	}
	log_debug("[+] Successfully set user program to trace");

	// PERF EVENT INITIALIZATION PART

	log_debug("[+] Creating blaze symbolizer...");
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		log_error("Fail to create a symbolizer");
		goto cleanup;
	}
	log_debug("[+] Successfully created blaze symbolizer");

	log_debug("[+] Creating a BPF perfbuffer manager...");
	perf_buf = perf_buffer__new(bpf_map__fd(skel->maps.perfmap), 8, handle_event, NULL, NULL, NULL);
	if (!perf_buf) {
		log_error("[!] Error creating perf buffer");
		goto cleanup;
	}
	log_debug("[+] Perfbuffer successfully created");

	log_debug("[+] Polling events from perfbuffer...");
	while ((ret = perf_buffer__poll(perf_buf, 100)) >= 0) {}

cleanup:
	if (skel)
		eptracer_bpf__destroy(skel);        
	if (symbolizer)
		blaze_symbolizer_free(symbolizer);
	if (perf_buf)
		perf_buffer__free(perf_buf);

}


int main(int argc, char **argv) 
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	bool *online_mask = NULL;
	int err = 0, num_cpus = 0, num_online_cpus = 0;
	struct stack_tracer_args stack_thread_arguments;
	pthread_t stack_tracer_thread;

	args.process_pid = "";
	args.process_name = "";
	args.verbose = false;
	args.log_file = "";
	
	/* Getting number of online cpus */
	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		log_error("[!] Failed to parse cpus number");
		return 1;	
	}

	/* Getting number of usable cpus */
	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		log_error("[!] Fail to get the number of processors");
		return 1;
	}
	
	/* Parsing command line arguments */
	err = argp_parse(&argp, argc, argv, 0, 0, &args);
	if (err) {
		log_error("[!] Error parsing program arguments");
		return 1;
	}

	/* Logging to file if requested */
	if (strlen(args.log_file) != 0) {
		f = fopen(args.log_file, "w+");
		if (!f) {
			log_error("[!] Failed to create logging file");
			return 1;	
		} else {
			if (log_add_fp(f, log_level) < 0) {
				log_error("[!] Failed to add logging file");
				return 1;
			} else {
				log_debug("[+] Successfully added logging file %s", args.log_file);
			}
		}
	}
	
	/* Handling libbpf errors and debug info callback */
	if (libbpf_set_print(libbpf_print_fn) < 0) {
		log_info("[!] Failed to initialize ePtracer in logging mode.");
	};

	log_debug("[+] PID: %s", args.process_pid);
	log_debug("[+] Process Name: %s", args.process_name);
	log_debug("[+] Verbose: %d", args.verbose);
	log_debug("[+] Log file: %s", args.log_file);
	
	stack_thread_arguments.online_mask = online_mask;
	stack_thread_arguments.num_cpus = num_cpus;
	stack_thread_arguments.num_online_cpus = num_online_cpus;

	if (pthread_create(&stack_tracer_thread, NULL, stack_tracer, (void*) &stack_thread_arguments)) {
		log_error("[!] Failed to create stack tracer thread.");
		return 1;
	}
	pthread_join(stack_tracer_thread, NULL);
	return 0;
}
