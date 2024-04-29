struct raw_syscalls_enter {
	unsigned short 	common_type;
	unsigned char 	common_flag;
	unsigned char   common_preempt_count;
	int common_pid; // can't actually use it

	long id;
	unsigned long args[6];
};
