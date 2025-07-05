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

#define MAX_ARGS 100
/* Max PID number is stated to be 4194304 (from sysctl -n kernel.pid_max) */
#define MAX_PID_LEN 10
#define MAX_STR_LEN 100

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
    printf("[+] Bye!");
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

/* create_execvp_args
 *
 * Description:
 * Parse program to trace and its and arguments from program arguments
 * to build up execvp arguments.
 *
 * Params: 
 * char *program: program string obtained from program agruments that will we used
 * to instantiate the process to trace.
 * char **execvp_file: execvp file
 * char **execvp_argv
 * */
static void create_execvp_args(char *program, char **execvp_file, char **execvp_argv)
{
    unsigned int arg_count = 0;
    
    /* If target program passed as arguments does not contain any argument */
    if (strstr(program, " ") == NULL) {
        *execvp_file = program;
        execvp_argv[0] = NULL;
        return;
    }
    
    /* Extract program name and its arguments */
    char *token = strtok(program, " ");
    while (token != NULL && arg_count < MAX_ARGS) {
        execvp_argv[arg_count++] = token;
        token = strtok(NULL, " ");
    }
    execvp_argv[arg_count] = NULL;
    *execvp_file = execvp_argv[0];
}

/*
 * get_PID_to_trace
 *
 * Description:
 * Returns the process identifier of the process that will be traced.  
 *
 * Return:
 * PID to trace.                      
 * If -P flag is passed, spawn a process and get its PID.                         
 * Return NULL if not able to attach to a valid PID.
 * 
 * */
char* get_PID_to_trace()
{	
	struct arguments *program_arguments = &args;
    char *execvp_file = (char*)malloc(sizeof(char) * MAX_STR_LEN + 1);
    char **execvp_argv = malloc(sizeof(char*) * MAX_ARGS + 1); 
    char *pid_to_trace_str = (char*)malloc(sizeof(char) * MAX_PID_LEN + 1);
    pid_t pid_to_trace;
    pid_t process_to_spawn;
    int pipe_fd[2];

	if (!program_arguments) {
		log_error("[!] Unexpected null program arguments.");
		return NULL;
	}
    
	if (program_arguments->process_pid && strlen(program_arguments->process_pid) != 0)
		return program_arguments->process_pid;
                    
	if (program_arguments->program && strlen(program_arguments->program) != 0) {
        if (strlen(program_arguments->program) > MAX_STR_LEN) {
            log_error("[!] Program length must be lower than %d!", MAX_STR_LEN);
            exit(1);
        }
        create_execvp_args(program_arguments->program, &execvp_file, execvp_argv);
        
        if (pipe(pipe_fd) == -1) {
            log_error("[!] Error while creating pipe");
            exit(1);
        }
        log_debug("[+] Pipe created successfully");

        process_to_spawn = fork();
        switch(process_to_spawn) {
        case -1:
            log_error("[!] Cannot spawn process to trace! (fork error)");
            exit(1);
        case 0:
            /* Communicating PID to trace to ePtracer */
            close(pipe_fd[0]);
            pid_to_trace = getpid();
            if (write(pipe_fd[1], &pid_to_trace, sizeof(pid_to_trace)) < 0) {
                log_error("[!] Error while sending PID to trace: %s", strerror(errno));
                exit(1);
            }
            log_debug("[+] PID to trace successfully sent to ePtracer");
            close(pipe_fd[1]);

            if (execvp(execvp_file, execvp_argv) == -1) {
                log_error("[!] Cannot spawn process to trace! (execvp error)");
                exit(1);
            }
        default:
            /* Reading tracer PID */
            close(pipe_fd[1]);
            if (read(pipe_fd[0], &pid_to_trace, sizeof(pid_to_trace)) < 0) {
                log_error("[!] Error while receiving PID to trace: %s", strerror(errno));
                exit(1);
            } 

            close(pipe_fd[0]);
            log_debug("[+] PID to trace received: %d", pid_to_trace);

            if (snprintf(pid_to_trace_str, MAX_PID_LEN, "%d", pid_to_trace) < 0) {
                log_error("[!] Error while convering PID to trace");
                exit(1);
            }
            return pid_to_trace_str;
        }
    }
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
 * char *process_identifier: process identifier obtained from get_PID_to_trace. 
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
		log_error("[!] Specified program identifier exceeds program max length.");
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
	log_debug("[+] Loading BPF program into kernel...");
	if (!skel) {
		skel = eptracer_bpf__open_and_load();
	} else {
		log_debug("[+] Using already loaded BPF program");
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
	char *process_id = (char*)malloc(sizeof(char) * MAX_PID_LEN);
	pthread_t threads[2];
	pthread_t stack_tracer_thread;
	pthread_t syscall_tracer_thread;
    
    /* Handling SIGINT */
    signal(SIGINT, cleanup);

	args.log_file = "";
	args.process_pid = "";
	args.program = "";
	args.show_stacktrace = false;
	args.show_syscall = false;
	args.verbose = false;
	
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
	if (args.log_file && strlen(args.log_file) != 0) {
		printf("[+] Logging ePtracer into: %s", args.log_file);
	}
	if (libbpf_set_print(libbpf_print_fn) < 0) {
		printf("[!] Failed to initialize ePtracer in logging mode.");
	};
	
	/* Get BPF skeleton to manage BPF objects in a easier way */
	skel = load_BPF_program();
	if (!skel) {
			log_error("[!] Error opening and loading BPF file");
			cleanup();
	}		
	log_debug("[+] BFP program correctly loaded");
	log_debug("[+] Setting user process to trace...");
	process_id = get_PID_to_trace(process_id);
    printf("PID_to_trace: %s", process_id);
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0) {
		log_error("[!] Error setting process to trace. Please make sure to specify one process to trace using PID or consider spawning a new one.");
		cleanup();
	}
	log_debug("[+] Successfully tracing process %s", process_id);

	log_debug("[+] Attaching to BPF program...");
	errno = eptracer_bpf__attach(skel);
	if (errno) { 
		log_error( "[!] Error finding BPF program");
		cleanup();
	}

	log_debug("[+] Successfully attached to BFP program");
	if (strncmp(args.process_pid, "", 1) != 0) {
		log_debug("[+] PID: %s", args.process_pid);
	}
	if (strncmp(args.program, "", 1) != 0) {
		log_debug("[+] Process Name: %s", args.program);
	}
	log_debug("[+] Verbose: %d", args.verbose);
	if (strncmp(args.log_file, "", 1) != 0) {
		log_debug("[+] Log file: %s", args.log_file);
	} else {
		log_debug("[+] No logging file specified, logging into stdout");
	}
	    
    /* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.");
	}	

	if (args.show_stacktrace) {
        stack_thread_arguments.online_mask = online_mask;
	    stack_thread_arguments.num_cpus = num_cpus;
	    stack_thread_arguments.num_online_cpus = num_online_cpus;
	    stack_thread_arguments.skel = skel;

		/* Creating thread that will handle communication with stack tracer BPF program */	
		if (pthread_create(&stack_tracer_thread, NULL, stack_tracer, (void*) &stack_thread_arguments)) {
			log_error("[!] Failed to create stack tracer thread.");
			cleanup();
		}
		threads[thread_index++] = stack_tracer_thread;
	}
	
	if (args.show_syscall) {
	    syscall_thread_arguments.skel = skel;
		/* Creating thread that will handle communication with syscall tracer BPF program */	
		if (pthread_create(&syscall_tracer_thread, NULL, syscall_tracer, (void*) &syscall_thread_arguments)) {
			log_error("[!] Failed to create syscall tracer thread.");
			cleanup();
		}
		threads[thread_index++] = syscall_tracer_thread;
	}

	if (!args.show_stacktrace && !args.show_syscall) {
		printf("[?] ePtracer is not tracing any event. To trace events, take a look at the usage using --help");
        return 0;
	}
  
	for (i = 0; i < thread_index; ++i) {
		pthread_join(threads[i], NULL);
	}
	
	return 0;
}
