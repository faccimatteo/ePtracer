#include <argp.h>
#include <stdbool.h>

static struct env {
	bool verbose;
} env;

const char *argp_program_version = "Ptracer-eBPF 0.0";
const char *argp_program_bug_address = "<875377@stud.unive.it>";
const char argp_program_doc[] = "\n\
              /$$                                                             \n\
             | $$                                                             \n\
  /00000   /$$$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$     \n\
 /00__  00 |_  $$_/    /$$__  $$ |____  $$  /$$____/  /$$__  $$  /$$__  $$    \n\
| 00  \\ 00   | $$     | $$  \\__/  /$$$$$$$ | $$      | $$$$$$$$ | $$  \\__/ \n\
| 00  | 00   | $$ /$$ | $$       /$$__  $$ | $$      | $$_____/ | $$          \n\
| 0000000/   |  $$$$/ | $$      |  $$$$$$$ |  $$$$$$ |  $$$$$$$ | $$          \n\
| 10____/     \\___/   |__/       \\_______/  \\______/  \\_______/ |__/      \n\
| 10                                                                          \n\
| 00                                                                          \n\
| 10                                                                          \n\
|__/ \n"
                                "\n"
                                "Ptracer-eBPF is a process analyzer which is capable of: \n"
                                " - tracing process system calls \n"
                                " - dump process stack frame to get a full overview about process call stack flow \n"
				" - understand previously writed custom rules to immediately block a unwanted behavior \n"
				"\n"
                                "USAGE: ./eptracer [-p <process_name>] [-P <pid>] [-v]\n";

static const struct argp_option opts[] = {
        { "verbose", 		'v', NULL, 0, "Verbose debug output" },
	{ "process to track", 	'p', NULL,0, "Process name you want to analyze" },
	{ "pid to track", 	'P', NULL,0, "PID you want to analyze" },
        {},
};



static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'v':
                env.verbose = true;
                break;
        case 'p':
                break;
	case 'P':
                break;
        case ARGP_KEY_ARG:
                argp_usage(state);
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
};

