
/* Permit pretty deep stack traces */
#define MAX_STACK_RAWTP 100
#define MAX_PROGRAM_STRING_LEN 100
#define MAX_PROGRAM_TO_TRACE 10

struct stack_trace_t {
  	int pid;
  	unsigned long kern_stack_size;
  	int user_stack_size;
  	__u64 kern_stack[MAX_STACK_RAWTP];
  	__u64 user_stack[MAX_STACK_RAWTP];
};

/* structure to send argument to stack_tracer thread */
struct stack_tracer_args 
{
	bool *online_mask;
	int num_cpus;
	int num_online_cpus;
    struct eptracer_bpf *skel; 
};

void *stack_tracer(void *stack_tracer_arguments);