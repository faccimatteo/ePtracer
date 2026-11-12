#include <assert.h>
#include <ctype.h>
#include <strings.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <bpf/bpf.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "include/args.h"
#include "include/bpf/blazesym.h"
#include "include/log.h"
#include "include/bpf/eptracer.skel.h"
#include "include/http_tracing.h"
#include "include/http_intercept.h"
#include "include/http_ca.h"
#include "include/http_ca_detect.h"
#include "include/stack_tracing.h"
#include "include/syscall_tracing.h"

/* Raised by the SIGINT/SIGTERM handler. The worker loops watch it so that they
 * leave their poll on their own, which is what lets the teardown run in a
 * normal context instead of from inside the signal handler. */
static volatile sig_atomic_t stop_requested = 0;

/* Privilege dropping for spawned and helper processes: declared here so the
 * tracer files included below (http_ca_detect.c runs certutil) can use them. */
#define EPTRACER_LOGIN_MAX 256
static int target_user_ids(uid_t *uid, gid_t *gid, char *name, size_t namesz);
static int drop_to_target_user(void);

#include "tracers/syscall.c"
#include "tracers/stacktrace.c"
#include "tracers/http.c"
#include "tracers/http_intercept.c"
#include "tracers/http_ca.c"
#include "tracers/http_ca_detect.c"

#define MAX_ARGS 100
/* Max PID number is stated to be 4194304 (from sysctl -n kernel.pid_max) */
#define MAX_PID_LEN 10
#define MAX_STR_LEN 100

extern int errno;
static struct arguments args;
static int log_level = LOG_DEBUG;
static FILE *f = NULL;
static struct eptracer_bpf *skel = NULL;
/* Write end of the pipe holding a spawned process on the starting line until
 * every probe is in place, so that no early traffic is missed */
static int child_start_fd = -1;

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

/**
 * cleanup
 *
 * Description:
 * cleanup resources if something goes wrong or SIGTERM has been captured
 *
 * */
void cleanup()
{
	/* Stops diverting connect(2) before the maps go away, or the traced
	 * process would keep being sent to a listener that no longer exists */
	http_intercept_stop();
	/* Drops the temporary CA bundle exported for the spawned process */
	http_ca_cleanup();

	if (skel) {
		eptracer_bpf__destroy(skel);
		skel = NULL;
    }
    sleep(1);
    printf("[+] Bye!");
    exit(0);
}

/*
 * on_signal
 *
 * Description:
 * SIGINT/SIGTERM handler. It does the one thing that is safe to do from a
 * signal handler — set a flag — and returns. The worker loops notice it and
 * leave, and main() then tears everything down in a normal context, where the
 * mutexes, joins and frees the teardown needs are actually allowed.
 *
 * Params:
 * int sig: signal number, unused.
 * */
static void on_signal(int sig)
{
	(void)sig;
	stop_requested = 1;
}

/*
 * libbpf_printf_fn
 *
 * Description:
 * Callback function invoked every time a log event is produced by libbpf.
 *
 * Params:
 * enum libbpf_print_level level: logging level used by libbpf. 
 * Checks https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.h#L90 for more details. 
 * const char *format: format needed to libbpf to produce our logs. 
 * va_list fn_args: arguments needed to libbpf to produce our logs.
 *
 * Return:
 * Number of bytes written to log file descriptor if verbose mode is activated, -1 otherwise.
 * */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list fn_args)
{

	/* Logs non-debug info if verbose is not requested */
	if (level > LIBBPF_INFO) {
		return 0;
	}

	if (args.log_file && strlen(args.log_file) != 0) {
        return vfprintf(f, format, fn_args);
	} else {
		return vfprintf(stdout, format, fn_args);
	}
	return -1;
}

/* create_execvp_args
 *
 * Description:
 * Parse program to trace and its and arguments from program arguments
 * to build up execvp arguments.
 *
 * Params: 
 * char *program: program string obtained from program agruments that will we used
 * to instantiate the process to trace.
 * char **execvp_file: execvp file
 * char **execvp_argv
 * */
static void create_execvp_args(char *program, char **execvp_file, char **execvp_argv)
{
    unsigned int arg_count = 0;
    
    /* If target program passed as arguments does not contain any argument */
    if (strstr(program, " ") == NULL) {
        *execvp_file = program;
        execvp_argv[0] = NULL;
        return;
    }
    
    /* Extract program name and its arguments */
    char *token = strtok(program, " ");
    while (token != NULL && arg_count < MAX_ARGS) {
        execvp_argv[arg_count++] = token;
        token = strtok(NULL, " ");
    }
    execvp_argv[arg_count] = NULL;
    *execvp_file = execvp_argv[0];
}

/*
 * target_user_ids
 *
 * Description:
 * Finds the unprivileged user ePtracer should run spawned and helper processes
 * as. Under sudo that is the invoking user, read from SUDO_UID/SUDO_GID (the
 * name from SUDO_USER, or resolved from the uid). There is nothing to drop to
 * when ePtracer was not started through sudo.
 *
 * Params:
 * uid_t *uid, gid_t *gid: receive the user and group ids.
 * char *name: receives the user name, for the supplementary groups.
 * size_t namesz: its size.
 *
 * Return:
 * 0 when an unprivileged target was found, -1 otherwise.
 * */
static int target_user_ids(uid_t *uid, gid_t *gid, char *name, size_t namesz)
{
	const char *sudo_uid = getenv("SUDO_UID");
	const char *sudo_gid = getenv("SUDO_GID");
	const char *sudo_user = getenv("SUDO_USER");

	if (!sudo_uid || !sudo_uid[0] || !sudo_gid || !sudo_gid[0])
		return -1;

	*uid = (uid_t)strtoul(sudo_uid, NULL, 10);
	*gid = (gid_t)strtoul(sudo_gid, NULL, 10);
	if (*uid == 0)
		return -1;

	if (name && namesz) {
		if (sudo_user && sudo_user[0]) {
			snprintf(name, namesz, "%s", sudo_user);
		} else {
			struct passwd *pw = getpwuid(*uid);

			snprintf(name, namesz, "%s", pw ? pw->pw_name : "");
		}
	}
	return 0;
}

/*
 * drop_to_target_user
 *
 * Description:
 * Drops the calling process from root to the invoking user, irreversibly, and
 * points HOME/USER/LOGNAME at that user so a spawned application reads its own
 * profile and trust store (the Chromium NSS database, for one). Meant to be
 * called in a forked child right before it execs. A no-op when ePtracer is not
 * running as root, or when there is no unprivileged user to drop to — in which
 * case the process stays as it is.
 *
 * Return:
 * 0 on success or when there was nothing to do, -1 when privileges could not be
 * dropped (the caller must then not exec, to avoid running as root unknowingly).
 * */
static int drop_to_target_user(void)
{
	char name[EPTRACER_LOGIN_MAX] = {0};
	struct passwd *pw = NULL;
	uid_t uid = 0;
	gid_t gid = 0;

	if (geteuid() != 0)
		return 0;

	if (target_user_ids(&uid, &gid, name, sizeof(name)) < 0) {
		log_debug("[?] No unprivileged user to drop to (not started via sudo); "
			  "the traced process will run as root");
		return 0;
	}

	pw = getpwuid(uid);
	if (pw) {
		setenv("HOME", pw->pw_dir, 1);
		setenv("USER", pw->pw_name, 1);
		setenv("LOGNAME", pw->pw_name, 1);
		if (pw->pw_shell && pw->pw_shell[0])
			setenv("SHELL", pw->pw_shell, 1);
	}

	/* Supplementary groups first, then gid, then uid: once the uid is gone
	 * the others can no longer be changed. */
	if (name[0] && initgroups(name, gid) < 0)
		log_debug("[?] Could not set supplementary groups for %s: %s",
			  name, strerror(errno));
	if (setgid(gid) < 0) {
		log_error("[!] setgid(%u) failed: %s", (unsigned)gid, strerror(errno));
		return -1;
	}
	if (setuid(uid) < 0) {
		log_error("[!] setuid(%u) failed: %s", (unsigned)uid, strerror(errno));
		return -1;
	}

	/* A dropped process must not be able to climb back to root */
	if (setuid(0) == 0) {
		log_error("[!] Privileges could be regained after dropping, aborting");
		return -1;
	}

	return 0;
}

/*
 * get_PID_to_trace
 *
 * Description:
 * Returns the process identifier of the process that will be traced.  
 *
 * Return:
 * PID to trace.                      
 * If -P flag is passed, spawn a process and get its PID.                         
 * Return NULL if not able to attach to a valid PID.
 * 
 * */
char* get_PID_to_trace()
{	
	struct arguments *program_arguments = &args;
    char *execvp_file = (char*)malloc(sizeof(char) * MAX_STR_LEN + 1);
    char **execvp_argv = malloc(sizeof(char*) * MAX_ARGS + 1); 
    char *pid_to_trace_str = (char*)malloc(sizeof(char) * MAX_PID_LEN + 1);
    pid_t pid_to_trace;
    pid_t process_to_spawn;
    int pipe_fd[2];
    int start_fd[2];
    char start_signal = 0;

	if (!program_arguments) {
		log_error("[!] Unexpected null program arguments.");
		return NULL;
	}
    
	if (program_arguments->process_pid && strlen(program_arguments->process_pid) != 0)
		return program_arguments->process_pid;
                    
	if (program_arguments->program && strlen(program_arguments->program) != 0) {
        if (strlen(program_arguments->program) > MAX_STR_LEN) {
            log_error("[!] Program length must be lower than %d!", MAX_STR_LEN);
            exit(1);
        }
        create_execvp_args(program_arguments->program, &execvp_file, execvp_argv);
        
        if (pipe(pipe_fd) == -1) {
            log_error("[!] Error while creating pipe");
            exit(1);
        }
        if (pipe(start_fd) == -1) {
            log_error("[!] Error while creating start pipe");
            exit(1);
        }
        log_debug("[+] Pipe created successfully");

        process_to_spawn = fork();
        switch(process_to_spawn) {
			case -1:
				log_error("[!] Cannot spawn process to trace! (fork error)");
				exit(1);
			case 0:
				/* Communicating PID to trace to ePtracer */
				close(pipe_fd[0]);
				pid_to_trace = getpid();
				if (write(pipe_fd[1], &pid_to_trace, sizeof(pid_to_trace)) < 0) {
					log_error("[!] Error while sending PID to trace: %s", strerror(errno));
					exit(1);
				}
				log_debug("[+] PID to trace successfully sent to ePtracer");
				close(pipe_fd[1]);

				/* Wait for ePtracer to finish attaching its probes. The
				 * write end is closed once every tracer is ready, which
				 * unblocks this read either way. */
				close(start_fd[1]);
				if (read(start_fd[0], &start_signal, sizeof(start_signal)) < 0) {
					log_error("[!] Error while waiting for ePtracer: %s", strerror(errno));
					exit(1);
				}
				close(start_fd[0]);

				/* Run the traced binary as the invoking user, not as
				 * root: GUI apps (Electron and the rest of Chromium)
				 * refuse to run as root, and a black-box binary should
				 * see its own profile and trust store. The probes stay
				 * loaded in the privileged parent, so nothing is lost. */
				if (drop_to_target_user() < 0) {
					log_error("[!] Refusing to run the traced process as root; "
						  "could not drop privileges");
					exit(1);
				}

				if (execvp(execvp_file, execvp_argv) == -1) {
					log_error("[!] Cannot spawn process to trace! (execvp error)");
					exit(1);
				}
				break;
			default:
				/* Reading tracer PID */
				close(pipe_fd[1]);
				if (read(pipe_fd[0], &pid_to_trace, sizeof(pid_to_trace)) < 0) {
					log_error("[!] Error while receiving PID to trace: %s", strerror(errno));
					exit(1);
				} 

				close(pipe_fd[0]);
				close(start_fd[0]);
				child_start_fd = start_fd[1];
				log_debug("[+] PID to trace received: %d", pid_to_trace);

				if (snprintf(pid_to_trace_str, MAX_PID_LEN, "%d", pid_to_trace) < 0) {
					log_error("[!] Error while convering PID to trace");
					exit(1);
				}
				return pid_to_trace_str;
				break;
        }
    }
    return NULL;
}

/* 
 * initialize_array  
 * 
 * Description:
 * Initializes the programs to trace.
 *
 * Params:
 * int fd: bpf map file descriptor for the current eptracer process.
 * char *process_identifier: process identifier obtained from get_PID_to_trace. 
 * This can be a PID or a name of a process. Note that process name might not correspond
 * to process name listed from `ps -aux`. Said so, consider prefer PID over process name
 * as program identifier.
 *
 * Return:
 * 0 on success, or a negative error in case of failure. 
 * For more details about bpf_map_update_elem error checks 
 * https://man7.org/linux/man-pages/man7/bpf-helpers.7.html#bpf_map_update_elem 
 *
 * PLANNED CHANGES:
 * By now, only one program is passed from program arguments.
 * Instead, the idea is to pass a list of process_identifier with a number of program 
 * to trace < MAX_PROGRAM_TO_TRACE.
 *
 * */
static int initialize_array(int fd, char *process_identifier)
{
	char name[MAX_PROGRAM_STRING_LEN];
	int bpf_error = 0;
	__u32 i = 0;

	if (strlen(process_identifier) > MAX_PROGRAM_STRING_LEN) {
		log_error("[!] Specified program identifier exceeds program max length.");
		return -1;
	}

	strncpy(name, process_identifier, MAX_PROGRAM_STRING_LEN);
    log_debug("[+] Starting tracing program: %s", name);

	/* Setting process to trace for all the CPUs */
    bpf_error = bpf_map_update_elem(fd, &i, &name, BPF_ANY);
	if (bpf_error < 0)
		log_error("[!] Failed to update BPF map with program name %s: error %d", name, bpf_error);

	return bpf_error;
}

/*
 * read_ppid
 *
 * Description:
 * Reads the parent of a process from /proc/<pid>/stat. The parent comes after
 * the command name, which is in parentheses and may contain spaces or
 * parentheses itself: it is located from the last ')'.
 *
 * Params:
 * pid_t pid: process to inspect.
 *
 * Return:
 * The parent PID, or -1 when the process is gone or unreadable.
 * */
static pid_t read_ppid(pid_t pid)
{
	char path[64], buf[512];
	char *close_paren = NULL;
	char state = 0;
	int ppid = -1;
	ssize_t len = 0;
	int fd = -1;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = '\0';

	close_paren = strrchr(buf, ')');
	if (!close_paren || sscanf(close_paren + 1, " %c %d", &state, &ppid) != 2)
		return -1;
	return (pid_t)ppid;
}

/*
 * follow_process_tree
 *
 * Description:
 * Seeds traced_tgids_map with the target and every process already below it,
 * for -F/--follow-forks. From then on the fork tracepoint keeps the map up to
 * date by itself. It runs after the programs are attached: a process forked
 * while /proc is being walked is then either caught by the tracepoint, because
 * its parent was already in the map, or found by the next pass. Passes are
 * repeated until one adds nothing.
 *
 * Params:
 * int fd: traced_tgids_map file descriptor.
 * pid_t root: process being traced.
 *
 * Return:
 * Number of processes followed, root included, or -1 on error.
 * */
static int follow_process_tree(int fd, pid_t root)
{
	__u8 one = 1, present = 0;
	__u32 key = (__u32)root;
	int followed = 1, added = 0, pass = 0;

	if (bpf_map_update_elem(fd, &key, &one, BPF_ANY) < 0) {
		log_error("[!] Failed to follow process %d: %s", root, strerror(errno));
		return -1;
	}

	for (pass = 0; pass < 8; pass++) {
		struct dirent *entry = NULL;
		DIR *proc = opendir("/proc");

		if (!proc) {
			log_error("[!] Cannot read /proc: %s", strerror(errno));
			return followed;
		}

		added = 0;
		while ((entry = readdir(proc)) != NULL) {
			pid_t pid = 0, ppid = 0;
			__u32 parent = 0;

			if (!isdigit((unsigned char)entry->d_name[0]))
				continue;
			pid = (pid_t)atoi(entry->d_name);
			key = (__u32)pid;
			if (bpf_map_lookup_elem(fd, &key, &present) == 0)
				continue;

			ppid = read_ppid(pid);
			if (ppid <= 0)
				continue;
			parent = (__u32)ppid;
			if (bpf_map_lookup_elem(fd, &parent, &present) != 0)
				continue;

			if (bpf_map_update_elem(fd, &key, &one, BPF_ANY) == 0) {
				log_debug("[+] Following child process %d (parent %d)", pid, ppid);
				added++;
			}
		}
		closedir(proc);

		/* readdir() order is not parent first: a grandchild listed
		 * before its parent is only matched on the next pass */
		followed += added;
		if (added == 0)
			break;
	}

	return followed;
}

/**
 * load_BPF_program
 *
 * Description:
 * Loads BPF program in kernel. 
 * Use already present one if already loaded.
 *
 * Return:
 * Skeleton associated to BPF program.
 *
 * */
/*
 * Keep only the BPF programs the requested features use. A program the kernel
 * rejects (an older verifier is stricter) would otherwise abort the whole
 * skeleton load, all-or-nothing; and loading what is not used is wasted. Pure
 * splice needs the redirect, the key capture and the load watches, not the
 * cleartext/syscall capture of -H.
 */
static void select_bpf_programs(struct eptracer_bpf *s, struct arguments *a, int splice)
{
	/* the cleartext HTTP capture over syscalls, and the Go TLS probes: only
	 * for -H, and never for splice (its keys come from the keylog probe) */
	struct bpf_program *http_only[] = {
		s->progs.probe_go_tls_write, s->progs.probe_go_tls_read_enter,
		s->progs.probe_go_tls_read_ret, s->progs.trace_sock_read_enter,
		s->progs.trace_sock_read_exit, s->progs.trace_sock_recvfrom_enter,
		s->progs.trace_sock_recvfrom_exit, s->progs.trace_sock_write_enter,
		s->progs.trace_sock_sendto_enter, s->progs.trace_raw_sock_enter,
		s->progs.trace_raw_sock_exit,
	};
	if (!a->show_http || splice)
		for (size_t i = 0; i < sizeof(http_only) / sizeof(*http_only); i++)
			bpf_program__set_autoload(http_only[i], false);
	if (!a->show_http) {
		bpf_program__set_autoload(s->progs.probe_ssl_write_enter, false);
		bpf_program__set_autoload(s->progs.probe_ssl_write_exit, false);
		bpf_program__set_autoload(s->progs.probe_ssl_write_ex_exit, false);
		bpf_program__set_autoload(s->progs.probe_ssl_read_enter, false);
		bpf_program__set_autoload(s->progs.probe_ssl_read_exit, false);
		bpf_program__set_autoload(s->progs.probe_ssl_read_ex_exit, false);
	}
	if (!a->show_stacktrace)
		bpf_program__set_autoload(s->progs.get_stacktrace, false);
	if (!a->show_syscall)
		bpf_program__set_autoload(s->progs.sys_enter_multiplexer, false);
	/* the TLS key capture is splice-only */
	if (!splice) {
		bpf_program__set_autoload(s->progs.probe_tls_keylog, false);
		bpf_program__set_autoload(s->progs.probe_tls_keylog_nss, false);
		bpf_program__set_autoload(s->progs.probe_hmac_sha256, false);
		bpf_program__set_autoload(s->progs.probe_hmac_sha512, false);
		bpf_program__set_autoload(s->progs.trace_exec, false);
		bpf_program__set_autoload(s->progs.trace_dlopen, false);
	}
}

static struct eptracer_bpf* load_BPF_program(struct arguments *a, int splice)
{
	log_debug("[+] Loading BPF program into kernel...");
	if (skel) {
		log_debug("[+] Using already loaded BPF program");
		return skel;
	}
	skel = eptracer_bpf__open();
	if (!skel)
		return NULL;
	select_bpf_programs(skel, a, splice);
	if (eptracer_bpf__load(skel)) {
		eptracer_bpf__destroy(skel);
		skel = NULL;
	}
	return skel;
}

/*
 * disable_http_autoattach
 *
 * Description:
 * The HTTP programs are attached on demand by the HTTP tracer: uprobes need a
 * library path that is only known at runtime, and the socket tracepoints must
 * not run at all when HTTP tracing was not requested.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * */
static void disable_http_autoattach(struct eptracer_bpf *skel)
{
	struct bpf_program *progs[] = {
		skel->progs.probe_ssl_write_enter,
		skel->progs.probe_ssl_write_exit,
		skel->progs.probe_ssl_write_ex_exit,
		skel->progs.probe_ssl_read_enter,
		skel->progs.probe_ssl_read_exit,
		skel->progs.probe_ssl_read_ex_exit,
		skel->progs.trace_connect_enter,
		skel->progs.trace_close_enter,
		skel->progs.trace_sock_write_enter,
		skel->progs.trace_sock_sendto_enter,
		skel->progs.trace_sock_read_enter,
		skel->progs.trace_sock_read_exit,
		skel->progs.trace_sock_recvfrom_enter,
		skel->progs.trace_sock_recvfrom_exit,
		/* The trust-store detection probes are attached by the CA
		 * detector, and only while interception is active */
		skel->progs.trace_openat_enter,
		skel->progs.trace_open_enter,
		/* raw_syscalls fallbacks, attached only when the per-syscall
		 * tracepoints above do not exist */
		skel->progs.trace_raw_sock_enter,
		skel->progs.trace_raw_sock_exit,
		skel->progs.trace_raw_open_enter,
		/* cgroup programs need a hierarchy to attach to, which only the
		 * interceptor knows about */
		skel->progs.intercept_connect4,
		skel->progs.intercept_connect6,
		skel->progs.intercept_getpeername4,
		/* placed by the TLS splice on the resolved keylog function, and the
		 * exec watch that tells it about new executables */
		skel->progs.probe_tls_keylog,
		skel->progs.probe_tls_keylog_nss,
		skel->progs.probe_hmac_sha256,
		skel->progs.probe_hmac_sha512,
		skel->progs.trace_exec,
		skel->progs.trace_dlopen,
	};
	size_t i = 0;

	for (i = 0; i < sizeof(progs) / sizeof(progs[0]); i++)
		bpf_program__set_autoattach(progs[i], false);
}

/*
 * release_traced_child
 *
 * Description:
 * Lets a process spawned with -p run: it has been blocked right before execvp()
 * since ePtracer started, so that the probes could be installed first.
 * Does nothing when ePtracer attached to an already running process.
 * */
static void release_traced_child()
{
	char go = 1;

	if (child_start_fd < 0)
		return;

	if (write(child_start_fd, &go, sizeof(go)) < 0)
		log_error("[!] Failed to release traced process: %s", strerror(errno));
	close(child_start_fd);
	child_start_fd = -1;
	log_debug("[+] Traced process released");
}

/*
 * wait_for_http_tracer
 *
 * Description:
 * Waits until the HTTP tracer has installed its probes, so that a spawned
 * process is not released before the uprobes are in place.
 *
 * Params:
 * int timeout_ms: how long to wait before giving up.
 * */
static void wait_for_http_tracer(int timeout_ms)
{
	int waited = 0;

	while (!http_tracer_ready && waited < timeout_ms) {
		usleep(10000);
		waited += 10;
	}

	if (!http_tracer_ready)
		log_error("[!] HTTP tracer still not ready after %d ms, starting anyway", timeout_ms);
}

/*
 * package_uid
 *
 * Description:
 * The uid of an installed Android package, from packages.list. Read through
 * init's root, so that it is found from inside a chroot (eadb) as well.
 *
 * Return:
 * The uid, -1 if the package is unknown.
 * */
static int package_uid(const char *package)
{
	static const char *const lists[] = { "/proc/1/root/data/system/packages.list",
					     "/data/system/packages.list" };
	char line[1024], name[256];
	int uid = -1;

	for (size_t i = 0; i < sizeof(lists) / sizeof(*lists) && uid < 0; i++) {
		FILE *f = fopen(lists[i], "re");
		if (!f)
			continue;
		while (uid < 0 && fgets(line, sizeof(line), f)) {
			int u = 0;
			if (sscanf(line, "%255s %d", name, &u) == 2 && strcmp(name, package) == 0)
				uid = u;
		}
		fclose(f);
	}
	return uid;
}

#include "tracers/preflight.c"

int main(int argc, char **argv) 
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	bool *online_mask = NULL;
	int err = 0, num_cpus = 0, num_online_cpus = 0, i = 0, thread_index = 0, fd = 0;
	struct stack_tracer_args stack_thread_arguments;
	struct syscall_tracer_args syscall_thread_arguments;
	struct http_tracer_args http_thread_arguments;
	/* get_PID_to_trace() returns either the -P string or a buffer it allocates
	 * itself, so there is nothing to preallocate here */
	char *process_id = NULL;
	pthread_t threads[4];
	pthread_t stack_tracer_thread;
	pthread_t syscall_tracer_thread;
	pthread_t http_tracer_thread;
	pthread_t ca_detect_thread;
	struct ca_detect_args ca_detect_arguments;
    
    /* Handling SIGINT and SIGTERM: the handler only raises a flag, the actual
     * teardown (the redirect has to come down or the traced process keeps being
     * sent to a port nobody listens on) runs in main(), in a normal context */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    /* A write to a socket whose peer already closed (an app cancelling an
     * HTTP/2 stream mid-search, a short-lived connection) raises SIGPIPE, whose
     * default action kills the process. Ignore it: the splice bridge checks
     * every write's return value and tears the one flow down on EPIPE. */
    signal(SIGPIPE, SIG_IGN);

#ifdef EPTRACER_STATIC
    /* The OpenSSL linked in is not the system's: its openssl.cnf may load
     * providers or engines this build does not have (openSUSE's does, with
     * config_diagnostics on, and every SSL_CTX_new() then fails). Must run
     * before any other OpenSSL call. */
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
#endif

	args.log_file = "";
	args.process_pid = "";
	args.program = "";
	args.ssl_lib = "";
	args.follow_forks = false;
	args.show_stacktrace = false;
	args.show_syscall = false;
	args.show_http = false;
	args.tls_only = false;
	args.http_only = false;
	args.http_decode = false;
	args.http_chunks = false;
	args.http_dump_dir = "";
	args.intercept = "";
	args.intercept_port = INTERCEPT_DEFAULT_PORT;
	args.intercept_ports = "";
	args.proxy_ca = "";
	args.tls_mode = "";
	args.splice_strict = false;
	args.splice_hold_ms = 0;
	args.bridge_port = 0;
	args.package = "";
	args.uid = 0;
	args.no_block_quic = false;
	args.verbose = false;
	args.check = false;
	
	/* Getting number of online cpus */
	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		log_error("[!] Failed to parse cpus number");
		return 1;	
	}

	/* Getting number of usable cpus */
	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		log_error("[!] Fail to get the number of processors");
		return 1;
	}
	
	/* Parsing command line arguments */
	err = parse_args(argc, argv, &args);
	if (err) {
		log_error("[!] Error parsing program arguments");
		return 1;
	}

	/* Logging to file if requested */
	if (strlen(args.log_file) != 0) {
		f = fopen(args.log_file, "w+");
		if (!f) {
			log_error("[!] Failed to create logging file");
			return 1;	
		} else {
			if (log_add_fp(f, log_level) < 0) {
				log_error("[!] Failed to add logging file");
				return 1;
			} else {
				log_debug("[+] Successfully added logging file %s", args.log_file);
			}
		}
	}
	
	/* Handling libbpf errors and debug info callback */
	if (args.log_file && strlen(args.log_file) != 0) {
		printf("[+] Logging ePtracer into: %s", args.log_file);
	}
	if (libbpf_set_print(libbpf_print_fn) < 0) {
		printf("[!] Failed to initialize ePtracer in logging mode.");
	};
	
	if (args.check)
		return run_preflight(args.verbose);

	int splice = args.tls_mode && strcasecmp(args.tls_mode, "splice") == 0;
	if (args.tls_mode && *args.tls_mode && !splice && strcasecmp(args.tls_mode, "mitm") != 0) {
		log_error("[!] --tls-mode is 'mitm' or 'splice', not '%s'", args.tls_mode);
		return 1;
	}
	if (splice && (!args.intercept || strlen(args.intercept) == 0)) {
		log_error("[!] --tls-mode splice needs -I/--intercept HOST:PORT (the proxy)");
		return 1;
	}

	/* Get BPF skeleton to manage BPF objects in a easier way */
	skel = load_BPF_program(&args, splice);
	if (!skel) {
		log_error("[!] Error opening and loading BPF file");
		cleanup();
		return 1;
	}		
	log_debug("[+] BFP program correctly loaded");
	disable_http_autoattach(skel);

	/* Trust the proxy CA for the process we are about to spawn, before the fork
	 * so the child inherits it. Only for a spawned process (-p): the trust is
	 * set through the environment, which an already running process (-P) cannot
	 * be given. 'direct' interception has no proxy CA to trust. */
	if (splice) {
		/* the app keeps the server's real certificate: nothing to trust */
	} else if (args.intercept && strlen(args.intercept) != 0 &&
	    args.program && strlen(args.program) != 0) {
		if (http_ca_autotrust(args.intercept, args.proxy_ca) < 0)
			log_error("[!] Proxy CA auto-trust is off: TLS interception will fail "
				  "unless the application already trusts the proxy CA");
	} else if (args.intercept && strlen(args.intercept) != 0 &&
		   args.process_pid && strlen(args.process_pid) != 0) {
		log_info("[?] Proxy CA auto-trust only applies to a spawned process (-p); "
			 "an attached process (-P) must already trust the proxy CA");
	}

	log_debug("[+] Setting user process to trace...");
	int target_uid = args.uid > 0 ? args.uid : -1;
	if (args.package && *args.package) {
		target_uid = package_uid(args.package);
		if (target_uid < 0) {
			log_error("[!] Package %s not found in packages.list", args.package);
			cleanup();
			return 1;
		}
		log_info("[+] Tracing every process of %s (uid %d)", args.package, target_uid);
	}
	if (target_uid >= 0) {
		/* an app by uid, now and later: no process to spawn or attach to */
		__u32 key = 0, value = (__u32)target_uid + 1;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uid_map), &key, &value, BPF_ANY) < 0) {
			log_error("[!] Cannot set the uid to trace");
			cleanup();
			return 1;
		}
		process_id = "0";
	} else {
		process_id = get_PID_to_trace();
	}
    printf("PID_to_trace: %s", process_id);
	if (!process_id || initialize_array(bpf_map__fd(skel->maps.program_map), process_id) < 0) {
		log_error("[!] Error setting process to trace. Please make sure to specify one process to trace using PID or consider spawning a new one.");
		cleanup();
		return 1;
	}
	log_debug("[+] Successfully tracing process %s", process_id);

	log_debug("[+] Attaching to BPF program...");
	
	errno = eptracer_bpf__attach(skel);
	if (errno) { 
		log_error( "[!] Error finding BPF program");
		cleanup();
		return 1;
	}

	log_debug("[+] Successfully attached to BFP program");

	/* Child processes have a TGID of their own: they are only traced when
	 * asked for, and seeded once the fork tracepoint is already running */
	if (args.follow_forks && target_uid < 0) {
		int followed = follow_process_tree(bpf_map__fd(skel->maps.traced_tgids_map),
						   (pid_t)atoi(process_id));

		if (followed < 0) {
			cleanup();
			return 1;
		}
		log_info("[+] Following the process tree of %s: %d process%s so far",
			 process_id, followed, followed == 1 ? "" : "es");
	}
	if (strncmp(args.process_pid, "", 1) != 0) {
		log_debug("[+] PID: %s", args.process_pid);
	}
	if (strncmp(args.program, "", 1) != 0) {
		log_debug("[+] Process Name: %s", args.program);
	}
	log_debug("[+] Verbose: %d", args.verbose);
	if (strncmp(args.log_file, "", 1) != 0) {
		log_debug("[+] Log file: %s", args.log_file);
	} else {
		log_debug("[+] No logging file specified, logging into stdout");
	}
	    
    /* Choosing fd where to log stack events */
	if (f)
		fd = fileno(f);
	else 
		fd = fileno(stdout);

	if (fd < 0) {
		log_error("[!] Failed to get file descriptor from stdio stream.");
	}	

	if (args.show_stacktrace) {
        stack_thread_arguments.online_mask = online_mask;
	    stack_thread_arguments.num_cpus = num_cpus;
	    stack_thread_arguments.num_online_cpus = num_online_cpus;
	    stack_thread_arguments.skel = skel;

		/* Creating thread that will handle communication with stack tracer BPF program */	
		if (pthread_create(&stack_tracer_thread, NULL, stack_tracer, (void*) &stack_thread_arguments)) {
			log_error("[!] Failed to create stack tracer thread.");
			cleanup();
			return 1;
		}
		threads[thread_index++] = stack_tracer_thread;
	}
	
	if (args.show_syscall) {
	    syscall_thread_arguments.skel = skel;
		/* Creating thread that will handle communication with syscall tracer BPF program */	
		if (pthread_create(&syscall_tracer_thread, NULL, syscall_tracer, (void*) &syscall_thread_arguments)) {
			log_error("[!] Failed to create syscall tracer thread.");
			cleanup();
			return 1;
		}
		threads[thread_index++] = syscall_tracer_thread;
	}

	if (args.show_http) {
		http_thread_arguments.skel = skel;
		http_thread_arguments.pid = (pid_t)atoi(process_id);
		http_thread_arguments.program = args.program;
		http_thread_arguments.ssl_lib = args.ssl_lib;
		http_thread_arguments.follow_forks = args.follow_forks;
		http_thread_arguments.tls_only = args.tls_only;
		http_thread_arguments.http_only = args.http_only;
		http_thread_arguments.chunk_view = args.http_chunks;
		http_thread_arguments.decode_bodies = args.http_decode;
		http_thread_arguments.dump_dir = args.http_dump_dir;

		/* Creating thread that will handle communication with HTTP tracer BPF programs */
		if (pthread_create(&http_tracer_thread, NULL, http_tracer, (void*) &http_thread_arguments)) {
			log_error("[!] Failed to create HTTP tracer thread.");
			cleanup();
			return 1;
		}
		threads[thread_index++] = http_tracer_thread;

		/* Uprobes are installed by the tracer thread: hold the spawned
		 * process until they are in place, HTTP exchanges are short lived */
		wait_for_http_tracer(5000);
	}

	/* The redirect has to be in place before a spawned process is let go,
	 * otherwise its first connections leave before anything is watching */
	if (args.intercept && strlen(args.intercept) != 0) {
		if (splice) {
			/* key probes first: the very first handshake must be seen */
			http_intercept_use_splice(args.splice_strict, args.splice_hold_ms,
						  args.bridge_port, args.proxy_ca);
			/* QUIC is not spliceable: make the app fall back to TCP */
			http_intercept_set_block_quic(!args.no_block_quic);
			splice_capture_start(skel, (pid_t)atoi(process_id), args.program,
					     args.ssl_lib);
			if (target_uid >= 0)
				splice_capture_uid((uid_t)target_uid);
		}
		if (http_intercept_start(skel, args.intercept, args.intercept_port,
					 args.intercept_ports) < 0)
			log_error("[!] Interception could not be started, the traced "
				  "process keeps talking to the network directly");
	}

	/* The trust store only matters when the proxy is a real man in the middle */
	if (args.intercept && strlen(args.intercept) != 0 && !splice) {
		/* With the proxy in the path the trust store suddenly matters:
		 * watch how the process decides what to trust, and import the
		 * proxy CA into an NSS database — the one class that can be
		 * trusted without touching the machine. 'direct' has no proxy
		 * CA, so detection runs but nothing is imported. */
		ca_detect_arguments.skel = skel;
		ca_detect_arguments.intercept = args.intercept;
		ca_detect_arguments.proxy_ca = args.proxy_ca;
		ca_detect_arguments.import =
			strcasecmp(args.intercept, INTERCEPT_UPSTREAM_DIRECT) != 0;
		if (pthread_create(&ca_detect_thread, NULL, ca_detect_tracer,
				   (void *)&ca_detect_arguments)) {
			log_error("[!] Failed to create the trust-store detection thread.");
		} else {
			int waited = 0;

			threads[thread_index++] = ca_detect_thread;
			/* Hold the spawned process until the openat probes are in
			 * place, so its very first trust-store open is captured */
			while (!ca_detect_ready && waited < 2000) {
				usleep(10000);
				waited += 10;
			}
		}

		/* A spawned NSS/Chromium app reads its trust store and finishes a
		 * handshake faster than the reactive import can run, so seed the
		 * proxy CA into the user's ~/.pki/nssdb now, before it is released */
		if (ca_detect_arguments.import && args.program && strlen(args.program) != 0)
			ca_preseed_nss(args.intercept, args.proxy_ca, args.program);
	}

	if (!args.show_stacktrace && !args.show_syscall && !args.show_http &&
	    (!args.intercept || strlen(args.intercept) == 0)) {
		printf("[?] ePtracer is not tracing any event. To trace events, take a look at the usage using --help");
		release_traced_child();
		http_ca_cleanup();
        return 0;
	}

	release_traced_child();

	/* Wait for a stop signal. The worker loops watch the same flag and leave
	 * their poll on their own, so joining them below returns without help, and
	 * interception on its own — which has no tracer thread — is covered too. */
	while (!stop_requested) {
		struct timespec pause = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

		nanosleep(&pause, NULL);
	}

	for (i = 0; i < thread_index; ++i) {
		pthread_join(threads[i], NULL);
	}

	/* Teardown in a normal context: mutexes, joins and frees are allowed here,
	 * unlike inside the signal handler that raised stop_requested */
	http_intercept_stop();
	http_ca_cleanup();
	if (skel) {
		eptracer_bpf__destroy(skel);
		skel = NULL;
	}
	return 0;
}
