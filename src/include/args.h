#include <stdbool.h>
#include <stddef.h>
#include "argparse.h"

struct arguments
{
	char *log_file;
	char *program;
	char *process_pid;
	int   show_stacktrace;
	int   show_syscall;
	int   verbose;
};

static const char *const eptracer_usages[] = {
	"eptracer [options]",
	NULL,
};

static const char eptracer_description[] =
	"\n"
	"              /$$                                                             \n"
	"             | $$                                                             \n"
	"  /00000   /$$$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$   /$$$$$$    /$$$$$$     \n"
	" /00__  00 |_  $$_/    /$$__  $$ |____  $$  /$$____/  /$$__  $$  /$$__  $$    \n"
	"| 00  \\ 00   | $$     | $$  \\__/  /$$$$$$$ | $$      | $$$$$$$$ | $$  \\__/ \n"
	"| 00  | 00   | $$ /$$ | $$       /$$__  $$ | $$      | $$_____/ | $$          \n"
	"| 0000000/   |  $$$$/ | $$      |  $$$$$$$ |  $$$$$$ |  $$$$$$$ | $$          \n"
	"| 10____/     \\___/   |__/       \\_______/  \\______/  \\_______/ |__/      \n"
	"| 10                                                                          \n"
	"| 00                                                  - by umadbro            \n"
	"| 10                                                                          \n"
	"|__/ \n"
	"\n"
	"ePtracer is a process analyzer which is capable of:\n"
	"- tracing process system calls\n"
	"- dumping a process backtrace to get a full overview of its call stack flow";

static int parse_args(int argc, char **argv, struct arguments *args)
{
	struct argparse_option opts[] = {
		OPT_HELP(),
		OPT_STRING ('f', "log-file",        &args->log_file,        "log to FILE instead of stdout", NULL, 0, 0),
		OPT_STRING ('p', "program",         &args->program,         "program to spawn and trace",    NULL, 0, 0),
		OPT_STRING ('P', "pid",             &args->process_pid,     "PID to attach to",              NULL, 0, 0),
		OPT_BOOLEAN('s', "show-stacktrace", &args->show_stacktrace, "trace process stack frames",    NULL, 0, 0),
		OPT_BOOLEAN('S', "show-syscall",    &args->show_syscall,    "trace process syscalls",        NULL, 0, 0),
		OPT_BOOLEAN('v', "verbose",         &args->verbose,         "verbose debug output",          NULL, 0, 0),
		OPT_END(),
	};

	struct argparse argparse;
	argparse_init(&argparse, opts, eptracer_usages, 0);
	argparse_describe(&argparse, eptracer_description, NULL);
	argparse_parse(&argparse, argc, (const char **)argv);
	return 0;
}
