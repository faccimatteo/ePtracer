#include <linux/bpf.h>

/* Permit pretty deep stack traces */
#define MAX_STACK_RAWTP 100
#define MAX_PROGRAM_STRING_LEN 100
#define MAX_PROGRAM_TO_TRACE 10

struct stack_trace_t {
  	__u32 pid;
  	__u32 kern_stack_size;
  	__u32 user_stack_size;
  	__u32 user_stack_buildid_size;
  	__u64 kern_stack[MAX_STACK_RAWTP];
  	__u64 user_stack[MAX_STACK_RAWTP];
	struct bpf_stack_build_id user_stack_buildid[MAX_STACK_RAWTP];
};


