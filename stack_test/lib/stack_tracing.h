#include <linux/bpf.h>

/* Permit pretty deep stack traces */
#define MAX_STACK_RAWTP 100
#define MAX_PROGRAM_STRING_LEN 100
#define MAX_PROGRAM_TO_TRACE 10

struct stack_trace_t {
  	int pid;
  	int kern_stack_size;
  	int user_stack_size;
  	__u64 kern_stack[MAX_STACK_RAWTP];
  	__u64 user_stack[MAX_STACK_RAWTP];
};
