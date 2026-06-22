#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>

static struct blaze_symbolizer *symbolizer = NULL;
static struct perf_buffer *perf_buf = NULL;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
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
		printf("0x%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		/* Log stack tracing information if */
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u", code_info->file, code_info->line);
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
			printf("0x%016llx: <no-symbol>\n", stack[i]);
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
	
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("--------------------------------------------------------------\n");
	printf("Time -> %-8s\n", ts);
	printf("PID -> %d\n", e->pid);
	printf("CPU -> %d\n", cpu);
	
	/* Showing kernel stack events if any */
	if (e->kern_stack_size > 0) {
	    printf("Kernel stack size -> %ld\n", e->kern_stack_size);
		printf("Kernel:\n");
		show_stack_trace(e->kern_stack, e->kern_stack_size / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	/* Showing user stack events if any */
	if (e->user_stack_size > 0) {
	    printf("User stack size -> %d\n", e->user_stack_size);
		printf("Userspace:\n");
		show_stack_trace(e->user_stack, e->user_stack_size / sizeof(__u64), e->pid);
	} else {
		printf("No Userspace Stack\n");
	}
	printf("--------------------------------------------------------------\n");
	/* Keep events spaced by one line */
	printf("\n");

}

void *stack_tracer(void *stack_tracer_arguments)
{
	bool *online_mask = NULL;
	int num_online_cpus = 0;
	int ret = 0, num_cpus = 0;
	int pid = -1, cpu = 0, i = 0;
	struct perf_event_attr attr;
	struct bpf_link **links;
    struct eptracer_bpf *skel;
	int *perfds = NULL;
    long perfd;

	/* Getting necessary params */
	online_mask = ((struct stack_tracer_args*) stack_tracer_arguments)->online_mask;
	num_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_cpus;
	num_online_cpus = ((struct stack_tracer_args*) stack_tracer_arguments)->num_online_cpus;
    skel = ((struct stack_tracer_args*) stack_tracer_arguments)->skel;

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
			// cleanup();
			return NULL;
		}
		perfds[cpu] = perfd;

		/* Assign each CPU a BPF program to analyze stack traces */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.get_stacktrace, perfd);
		if (!links[cpu]) {
			// cleanup();
			return NULL;
		}
	}

	/* PERF EVENT INITIALIZATION PART */

	log_debug("[+] Creating blaze symbolizer...\n");
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		log_error("Fail to create a symbolizer\n");
		// cleanup();
		return NULL;
	}
	log_debug("[+] Successfully created blaze symbolizer\n");

	log_debug("[+] Creating a BPF perfbuffer manager...\n");
	perf_buf = perf_buffer__new(bpf_map__fd(skel->maps.perfmap), 8, stack_event_handler, NULL, NULL, NULL);
	if (!perf_buf) {
		log_error("[!] Error creating perf buffer manager\n");
		// cleanup();
		return NULL;
	}
	log_debug("[+] Perf buffer successfully created\n");
	log_debug("[+] Polling events from perf buffer...\n");
	while ((ret = perf_buffer__poll(perf_buf, 100)) >= 0) {}
	return NULL;
}
