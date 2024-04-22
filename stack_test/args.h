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
| 00                                                  - by umadbro             \n\
| 10                                                                          \n\
|__/ \n"
                                "\n"
                                "Ptracer-eBPF is a process analyzer which is capable of: \n"
                                " - tracing process system calls \n"
                                " - dump process stack frame to get a full overview about process call stack flow \n"
				" - parse custom rules to immediately block a unwanted behavior \n"
				"\n"
                                "USAGE: ./eptracer [-p <process_name>] [-P <pid>] [-v]\n";

static const struct argp_option argp_opts[] = {
        { "verbose", 												'v', 0, 		0, "Verbose debug output", 0 },
				{ "name of the process to track", 	'p', "NAME",	0, "Process name you want to analyze", 0 },
				{ "pid of the process to track", 		'P', "PID",		0, "PID you want to analyze", 0 },
				{ "logging file", 									'f', "FILE", 	0, "Logging to file instead of standard output", 0 },
        {},
};

struct arguments
{
  	char *process_name;
  	char *process_pid;
  	int verbose;
  	char *log_file;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	 struct arguments *args = state->input;
	
  switch (key) 
	{
		case 'v':
			args->verbose = true;
			break;
		case 'p':
			args->process_name = arg;
			break;
		case 'P':
			args->process_pid= arg;
			break;
		case 'f':
			args->log_file = arg;
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
