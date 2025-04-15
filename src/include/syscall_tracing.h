/* Used by exec syscall */
#define ARGV_MAX_SIZE 5
#define ENVP_MAX_SIZE 3
/* Max string length used inside eBPF programs */
#define MAX_LEN 128 

/* Maximum redable system calll buffer size */
#define MAX_BUF_SIZE 32

struct raw_syscall_t {
	char *program_name;
	__u32 pid;
	__u32 tgid;
	__u64 syscall_id;
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

struct syscall_execve_enter {
    /* 
      First 4 fields are not used but necessary to get the 
      right value for the next fields in the structure
    */
    unsigned short  common_type;
    unsigned char   common_flags;
    unsigned char   common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
};


struct syscall_enter {
    __u32 pid;
    long id;
    
    unsigned char rdi;
    unsigned char rsi;
    unsigned char rdx;
    unsigned char r10;
    unsigned char r8;
    unsigned char r9;
};
