#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "get-stacktrace.h"
#include "get_stacktrace.skeleton.h"
#include "./log/src/log.h"

extern int errno;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct stack_trace_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int i, j, row_size, num_rows = 0;
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	log_info("[+] System call detected");
	log_info("Time ->  %-8s", ts);
	log_info("PID -> %d", e->pid);
	log_info("Kernel stack size -> %d", e->kern_stack_size);
	log_info("User stack size -> %d", e->user_stack_size);

	/*
	log_info("Dumping kernel stack data [%d]", MAX_STACK_RAWTP);
	   for(i = 0; i < MAX_STACK_RAWTP; ++i) {
		printf("%llu", e->kern_stack[i]);
	}*/
		
	log_info("Dumping user stack data [%d bytes]", MAX_STACK_RAWTP);

	num_rows = 5;
	row_size = MAX_STACK_RAWTP / num_rows;	
	for(i = 0; i < num_rows; ++i) {
		for(j = 0; j < row_size; ++j) {
			printf("%llu ", e->user_stack[i]);        
		}
		printf("\n");
	}
	log_info("-----------------------------------------------");

}

int main(int argc, char **argv) 
{
    struct get_stacktrace_bpf *skel;
    struct perf_buffer *perf_buf;
    int ret = 0; 

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    log_info("[+] Loading BPF program into kernel...");
    skel = get_stacktrace_bpf__open_and_load();
    if (!skel) {
        log_error("[!] Error opening and loading BPF file");
        return 1;
    }
    log_info("[+] BFP program correctly loaded");

    
    log_info("[+] Attaching to BPF program...");
    errno = get_stacktrace_bpf__attach(skel);
    if (errno) { 
        log_error( "[!] Error finding BPF program");
        get_stacktrace_bpf__destroy(skel);
        return 1;
    }
    log_info("[+] Successfully attached to BFP program");
    
    log_info("[+] Creating a BPF perfbuffer manager...");
    perf_buf = perf_buffer__new(bpf_map__fd(skel->maps.perfmap), 8, handle_event, NULL, NULL, NULL);
    if (!perf_buf) {
        log_error("[!] Error creating perf buffer");
        get_stacktrace_bpf__destroy(skel);        
        return 1;
    }
    log_info("[+] Perfbuffer successfully created");
    
    log_info("[+] Polling events from perfbuffer...");
    while ((ret = perf_buffer__poll(perf_buf, 100)) >= 0) {}

    perf_buffer__free(perf_buf);
    get_stacktrace_bpf__destroy(skel);        

    return 0;
}
