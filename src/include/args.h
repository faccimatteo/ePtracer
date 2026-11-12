#include <stdbool.h>
#include <stddef.h>
#include "argparse.h"

struct arguments
{
	char *log_file;
	char *program;
	char *process_pid;
	char *ssl_lib;
	int   follow_forks;
	int   show_stacktrace;
	int   show_syscall;
	int   show_http;
	int   tls_only;
	int   http_only;
	int   http_decode;
	int   http_chunks;
	char *http_dump_dir;
	char *intercept;
	int   intercept_port;
	char *intercept_ports;
	char *proxy_ca;
	char *tls_mode;
	int   splice_strict;
	int   splice_hold_ms;
	int   bridge_port;
	char *package;
	int   uid;
	int   no_block_quic;
	int   verbose;
	int   check;
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
	"- dumping a process backtrace to get a full overview of its call stack flow\n"
	"- decoding the HTTP traffic it exchanges, TLS included: payloads are read\n"
	"  inside the process itself, so certificate pinning does not apply\n"
	"- putting an intercepting proxy in the path of the traced process, which\n"
	"  eBPF does without configuring the application nor touching the routing.\n"
	"  When a spawned process is intercepted, the proxy CA is trusted for it\n"
	"  automatically, so TLS interception needs no manual certificate setup";

static int parse_args(int argc, char **argv, struct arguments *args)
{
	struct argparse_option opts[] = {
		OPT_HELP(),
		OPT_STRING ('f', "log-file",        &args->log_file,        "log to FILE instead of stdout", NULL, 0, 0),
		OPT_STRING ('p', "program",         &args->program,         "program to spawn and trace",    NULL, 0, 0),
		OPT_STRING ('P', "pid",             &args->process_pid,     "PID to attach to",              NULL, 0, 0),
		OPT_STRING ('L', "ssl-lib",         &args->ssl_lib,         "comma separated TLS libraries to hook, every known ABI is tried on each (default: autodetect OpenSSL, NSS, GnuTLS, wolfSSL, mbedTLS)", NULL, 0, 0),
		OPT_BOOLEAN('F', "follow-forks",    &args->follow_forks,    "trace the child processes of the target too, the ones it already has and the ones it forks", NULL, 0, 0),
		OPT_BOOLEAN('s', "show-stacktrace", &args->show_stacktrace, "trace process stack frames",    NULL, 0, 0),
		OPT_BOOLEAN('S', "show-syscall",    &args->show_syscall,    "trace process syscalls",        NULL, 0, 0),
		OPT_BOOLEAN('H', "show-http",       &args->show_http,       "decode process HTTP traffic (TLS and cleartext)", NULL, 0, 0),
		OPT_BOOLEAN('t', "tls-only",        &args->tls_only,        "capture TLS traffic only, ignore cleartext sockets", NULL, 0, 0),
		OPT_BOOLEAN('o', "http-only",       &args->http_only,       "drop captured payloads that do not look like HTTP", NULL, 0, 0),
		OPT_BOOLEAN('d', "http-decode",     &args->http_decode,     "unchunk and decompress message bodies, restating the headers that describe them", NULL, 0, 0),
		OPT_STRING ('D', "http-dump-dir",   &args->http_dump_dir,   "write each raw message to its own file in DIR", NULL, 0, 0),
		OPT_BOOLEAN( 0 , "http-chunks",     &args->http_chunks,     "show the captured chunks live instead of reassembling messages", NULL, 0, 0),
		OPT_STRING ('I', "intercept",       &args->intercept,       "put an intercepting proxy in the path of the traced process (HOST:PORT, default 127.0.0.1:8080; 'direct' relays to the real servers)", NULL, 0, 0),
		OPT_INTEGER( 0 , "intercept-port",  &args->intercept_port,  "loopback port the redirected connections land on (default: 8081)", NULL, 0, 0),
		OPT_STRING ( 0 , "intercept-ports", &args->intercept_ports, "comma separated destination ports to intercept (default: every TCP port)", NULL, 0, 0),
		OPT_STRING ( 0 , "proxy-ca",        &args->proxy_ca,        "proxy CA certificate to trust for the spawned process (PEM or DER); autodetected from the proxy when omitted", NULL, 0, 0),
		OPT_STRING ( 0 , "tls-mode",        &args->tls_mode,        "with -I: 'mitm' (default) tunnels TLS to the proxy, which presents its own certificate; 'splice' keeps the app's session with the real server (pinning holds, no CA to trust) and decrypts it with the keys read inside the process", NULL, 0, 0),
		OPT_INTEGER( 0 , "bridge-port",     &args->bridge_port,     "splice: port the proxy uses as its upstream proxy (default: 8082)", NULL, 0, 0),
		OPT_BOOLEAN( 0 , "splice-strict",   &args->splice_strict,   "splice: close a connection rather than let through anything the proxy could not see (no key, TLS 1.2, not HTTP)", NULL, 0, 0),
		OPT_INTEGER( 0 , "splice-hold-ms",  &args->splice_hold_ms,  "splice: how long a client record waits for its key (default: 200)", NULL, 0, 0),
		OPT_STRING ( 0 , "package",         &args->package,         "trace every process of this Android app (its uid, from packages.list), started now or later", NULL, 0, 0),
		OPT_INTEGER( 0 , "uid",             &args->uid,             "trace every process running as this uid", NULL, 0, 0),
		OPT_BOOLEAN( 0 , "no-block-quic",   &args->no_block_quic,   "splice: do not refuse the target's UDP/443 (leave QUIC/HTTP3 flowing, uncaptured)", NULL, 0, 0),
		OPT_BOOLEAN( 0 , "check",           &args->check,           "check whether this kernel can run ePtracer (BTF, ring buffers, every BPF program through the verifier) and exit", NULL, 0, 0),
		OPT_BOOLEAN('v', "verbose",         &args->verbose,         "verbose debug output",          NULL, 0, 0),
		OPT_END(),
	};

	struct argparse argparse;
	argparse_init(&argparse, opts, eptracer_usages, 0);
	argparse_describe(&argparse, eptracer_description, NULL);
	argparse_parse(&argparse, argc, (const char **)argv);
	return 0;
}
