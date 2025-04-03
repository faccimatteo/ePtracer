#include <argp.h>
#include <assert.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "include/args.h"
#include "include/bpf/blazesym.h"
#include "include/log.h"
#include "include/bpf/eptracer.skel.h"
#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"
#include "tracers/syscall.c"
#include "tracers/stacktrace.c"

extern int errno;
static struct arguments args;
static int log_level = LOG_DEBUG;
static FILE *f = NULL;
static struct eptracer_bpf *skel = NULL;

/**
 * cleanup
 *
 * Description:
 * cleanup resources if something goes wrong or SIGTERM has been captured
 *
 * */
void cleanup() 
{
	if (skel) {
		eptracer_bpf__destroy(skel);        
		skel = NULL;
    }
    sleep(1);
    printf("[+] Bye!\n");
    exit(0);
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

int main(int argc, char **argv) 
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	bool *online_mask = NULL;
	int err = 0, num_cpus = 0, num_online_cpus = 0, i = 0, thread_index = 0, fd = 0;
	struct stack_tracer_args stack_thread_arguments;
	struct syscall_tracer_args syscall_thread_arguments;
	char *process_id = NULL;
	pthread_t threads[2];
	pthread_t stack_tracer_thread;
	pthread_t syscall_tracer_thread;
    
    /* Handling SIGINT */
    signal(SIGINT, cleanup);

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
		f = fopen(args.log_file, "w+");
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
	}		
	log_debug("[+] BFP program correctly loaded\n");

	log_debug("[+] Setting user process to trace...\n");
	process_id = get_process_identifier();
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0) {
		log_error("[!] Error setting process to trace. Please make sure to specify one process to trace using PID or name identifier.\n");
		cleanup();
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
	    
    /* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.\n");
	}	

	if (args.show_stacktrace) {
        stack_thread_arguments.online_mask = online_mask;
	    stack_thread_arguments.num_cpus = num_cpus;
	    stack_thread_arguments.num_online_cpus = num_online_cpus;
	    stack_thread_arguments.skel = skel;

		/* Creating thread that will handle communication with stack tracer BPF program */	
		if (pthread_create(&stack_tracer_thread, NULL, stack_tracer, (void*) &stack_thread_arguments)) {
			log_error("[!] Failed to create stack tracer thread.\n");
			cleanup();
		}
		threads[thread_index++] = stack_tracer_thread;
	}
	
	if (args.show_syscall) {
	    syscall_thread_arguments.skel = skel;
		/* Creating thread that will handle communication with syscall tracer BPF program */	
		if (pthread_create(&syscall_tracer_thread, NULL, syscall_tracer, (void*) &syscall_thread_arguments)) {
			log_error("[!] Failed to create syscall tracer thread.\n");
			cleanup();
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
