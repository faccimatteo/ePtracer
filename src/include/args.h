#include <argp.h>
#include <stdbool.h>

#define MAX_PROGRAM_ARGS 4 

const char *argp_program_version = "Ptracer-eBPF 0.0-alpha";
const char *argp_program_bug_address = "<875377@stud.unive.it>";
static const char argp_program_doc[] = "\n\
              /$$                                                             \n\
             | $$                                                             \n\
  /00000   /$$$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$     \n\
 /00__  00 |_  $$_/    /$$__  $$ |____  $$  /$$____/  /$$__  $$  /$$__  $$    \n\
| 00  \\ 00   | $$     | $$  \\__/  /$$$$$$$ | $$      | $$$$$$$$ | $$  \\__/ \n\
| 00  | 00   | $$ /$$ | $$       /$$__  $$ | $$      | $$_____/ | $$          \n\
| 0000000/   |  $$$$/ | $$      |  $$$$$$$ |  $$$$$$ |  $$$$$$$ | $$          \n\
| 10____/     \\___/   |__/       \\_______/  \\______/  \\_______/ |__/      \n\
| 10                                                                          \n\
| 00                                                  - by umadbro            \n\
| 10                                                                          \n\
|__/ \n"
                                "\n"
                                "Ptracer-eBPF is a process analyzer which is capable of: \n"
                                " - tracing process system calls \n"
                                " - dump process stack frame to get a full overview about process call stack flow \n"
				" - parse custom rules to immediately block a unwanted behavior \n"
				"\n"
                                "USAGE: ./eptracer [-p <process_name>] [-P <pid>] [-S -s -v]\n";

static const struct argp_option argp_opts[] = {
        { "verbose", 												'v', 0,									0, "Verbose debug output", 												0 },
				{ "name", 													'p', "NAME",						0, "Process name you want to analyze", 						0 },
				{ "pid", 														'P', "PID",							0, "PID you want to analyze", 										0 },
				{ "show-stacktrace", 								's', 0,									0, "trace process stack calls", 									0 },
				{ "show-syscall", 									'S', 0,									0, "trace process stack calls", 									0 },
				{ "log-file", 											'f', "FILE", 						0, "Logging to file instead of standard output", 	0 },
        {},
};

struct arguments
{
  	char *log_file;
  	char *process_name;
  	char *process_pid;
		int show_stacktrace;
		int show_syscall;
  	int verbose;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *args = state->input;
  switch (key) 
	{
		case 'f':
			args->log_file = arg;
			break;
		case 'p':
			args->process_name = arg;
			break;
		case 'P':
			args->process_pid = arg;
			break;
		case 's':
			args->show_stacktrace = true;
			break;
		case 'S':
			args->show_syscall = true;
			break;
		case 'v':
			args->verbose = true;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num > MAX_PROGRAM_ARGS)
				argp_usage(state);
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}


static struct argp argp = {
  .options = argp_opts,
  .parser = parse_arg,
  .doc = argp_program_doc,
};
