#include <linux/bpf.h>

struct raw_syscall_t {
	char *program_name;
	__u32 pid;
	__u32 tgid;
	__u32 syscall_id;
	__u64 args[6];
};

struct raw_syscalls_enter {
	unsigned short 	common_type;
	unsigned char 	common_flag;
	unsigned char   common_preempt_count;
	int common_pid; // can't actually use it

	long id;
	unsigned long args[6];
};
