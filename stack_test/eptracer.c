#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include "args.h"
#include "get-stacktrace.h"
#include "eptracer.skeleton.h"
#include "./log/src/log.h"

extern int errno;
static struct arguments args;
static int log_level = LOG_DEBUG;
static FILE *f = NULL;

/*
 * libbpf_printf_fn
 *
 * Description:
 * Callback function invoked every time a log event is produced by libbpf.
 *
 * Params:
 * enum libbpf_print_level level: logging level used by libbpf. Checks https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.h#L90 for more details. 
 * const char *format: format needed to libbpf to produce our logs. 
 * va_list fn_args: arguments needed to libbpf to produce our logs.
 *
 * Return:
 * Number of bytes written to log file descriptor if verbose mode is activated, 
 * -1 otherwise.
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
 * Params:
 * struct arguments *args represents 
 *
 * Return:
 * Always use PID first.                      
 * Otherwise if cannot use PID, use process name.                         
 * Return NULL if no PID nor process name are defined.
 * 
 * */
static char* get_process_identifier(struct arguments *args)
{
		if (!args)
			return NULL;
		if (args->process_pid && strlen(args->process_pid) != 0)
			return args->process_pid;
		if (args->process_name && strlen(args->process_name) != 0)
			return args->process_name;
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
 * For more details about bpf_map_update_elem error checks https://man7.org/linux/man-pages/man7/bpf-helpers.7.html#bpf_map_update_elem 
 *
 * PLANNED CHANGES:
 * By now, only one program is passed from program arguments.
 * Instead, the idea is to pass a list of process_identifier with a number of program 
 * to trace < MAX_PROGRAM_TO_TRACE.
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
 * */
static void handle_event(void *ctx, int cpu, void *stack_data, __u32 stack_size)
{
	const struct stack_trace_t *e = stack_data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int i, j, row_size, num_rows = 0;
	int fd;

	/* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.");
		return;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	log_info("[+] System call detected");
	log_info("Time ->  %-8s", ts);
	log_info("PID -> %d", e->pid);
	log_info("Kernel stack size -> %d", e->kern_stack_size);
	log_info("User stack size -> %d", e->user_stack_size);

	/*
	log_debug("Dumping kernel stack stack [%d]", MAX_STACK_RAWTP);
	   for(i = 0; i < MAX_STACK_RAWTP; ++i) {
		log_info("%llu", e->kern_stack[i]);
	}*/
		
	log_info("Dumping user stack stack [%d addresses]", e->user_stack_size);

	num_rows = 5;
	row_size = e->user_stack_size / num_rows;	
	for(i = 0; i < num_rows; ++i) {
		for(j = 0; j < row_size; ++j) {
			dprintf(fd, "%llu ", e->user_stack[(i * row_size) + j]);        
		}
		dprintf(fd, "\n");
	}
	dprintf(fd, "-----------------------------------------------\n");
}

int main(int argc, char **argv) 
{
	struct eptracer_bpf *skel;
	struct perf_buffer *perf_buf;
	int err, ret = 0;
	char* process_id = NULL;

	args.process_pid = "";
	args.process_name = "";
	args.verbose = false;
	args.log_file = "";

	/* Parsing command line arguments */
	err = argp_parse(&argp, argc, argv, 0, 0, &args);
  if (err)
		return err;

	/* Logging to file if requested */
	if (strlen(args.log_file) != 0) {
		f = fopen(args.log_file, "w+");
		if (!f) {
			log_error("[!] Failed to create logging file");
			return 1;	
		} else {
			if (log_add_fp(f, log_level) < 0) {
				log_error("[!] Failed to add logging file");
			} else {
				log_debug("[+] Successfully added logging file %s", args.log_file);
			}
		}
	}
	
	/* Handling libbpf errors and debug info callback */
	if (libbpf_set_print(libbpf_print_fn) < 0) {
		log_info("[!] ePtracer has been initialized in non-logging mode.");
	};

	log_debug("[+] PID: %s", args.process_pid);
	log_debug("[+] Process Name: %s", args.process_name);
	log_debug("[+] Verbose: %d", args.verbose);
	log_debug("[+] Log file: %s", args.log_file);

	log_debug("[+] Loading BPF program into kernel...");
	skel = eptracer_bpf__open_and_load();
	if (!skel) {
		log_error("[!] Error opening and loading BPF file");
		return 1;
	}
	log_debug("[+] BFP program correctly loaded");


	log_debug("[+] Attaching to BPF program...");
	errno = eptracer_bpf__attach(skel);
	if (errno) { 
		log_error( "[!] Error finding BPF program");
		eptracer_bpf__destroy(skel);
		return 1;
	}
	log_debug("[+] Successfully attached to BFP program");

	log_debug("[+] Setting user program to trace...");
	process_id = get_process_identifier(&args);
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0)
	{
		log_error("[!] Error setting program to trace");
		eptracer_bpf__destroy(skel);
		return 1;
	}
	log_debug("[+] Successfully set user program to trace");


	log_debug("[+] Creating a BPF perfbuffer manager...");
	perf_buf = perf_buffer__new(bpf_map__fd(skel->maps.perfmap), 8, handle_event, NULL, NULL, NULL);
	if (!perf_buf) {
		log_error("[!] Error creating perf buffer");
		eptracer_bpf__destroy(skel);        
		return 1;
	}
	log_debug("[+] Perfbuffer successfully created");

	log_debug("[+] Polling events from perfbuffer...");
	while ((ret = perf_buffer__poll(perf_buf, 100)) >= 0) {}

	perf_buffer__free(perf_buf);
	eptracer_bpf__destroy(skel);        

	return 0;
}
