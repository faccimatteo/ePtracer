/*
 * Trust-store detection, and the targeted NSS import that follows from it.
 *
 * The rationale is in include/http_ca_detect.h. This file polls the cert-store
 * opens the BPF side filtered out of every open(2)/openat(2), reports how each
 * traced process decides what to trust, and — for the one class where it can be
 * done without touching the machine — imports the proxy CA into the exact NSS
 * database the process was seen opening.
 *
 * It is #included into the eptracer.c translation unit, after http_ca.c, whose
 * http_ca_proxy_ca_file() it calls to get the CA to import.
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Processes whose trust mechanism has already been reported, so the line is
 * printed once rather than on every cert-store open the process makes */
#define CA_MAX_SEEN_PIDS   256
/* NSS databases already handed to certutil, so the import runs once per db */
#define CA_MAX_SEEN_DBS    64

static struct ring_buffer *ca_ring_buf = NULL;
static struct bpf_link *ca_links[2];
static int ca_link_count = 0;
/* Raised once the probes are in place, read by main() before a spawned process
 * is released so its startup opens are not missed */
volatile int ca_detect_ready = 0;

/* Whether the NSS import should be attempted (off for 'direct' interception) */
static int ca_do_import = 0;
/* --intercept / --proxy-ca, kept so the proxy CA can be obtained on demand */
static const char *ca_intercept = NULL;
static const char *ca_proxy_ca = NULL;

static __u32 ca_seen_pids[CA_MAX_SEEN_PIDS];
static int ca_seen_pid_count = 0;
static char ca_seen_dbs[CA_MAX_SEEN_DBS][PATH_MAX];
static int ca_seen_db_count = 0;

/*
 * ca_pid_first_seen
 *
 * Description:
 * Records a PID and reports whether this is the first cert-store open seen from
 * it, so the mechanism is logged once.
 * */
static int ca_pid_first_seen(__u32 pid)
{
	int i = 0;

	for (i = 0; i < ca_seen_pid_count; i++) {
		if (ca_seen_pids[i] == pid)
			return 0;
	}
	if (ca_seen_pid_count < CA_MAX_SEEN_PIDS)
		ca_seen_pids[ca_seen_pid_count++] = pid;
	return 1;
}

/*
 * ca_db_first_seen
 *
 * Description:
 * Records an NSS database directory and reports whether it is new, so certutil
 * is run once per database however many times the process reopens it.
 * */
static int ca_db_first_seen(const char *dir)
{
	int i = 0;

	for (i = 0; i < ca_seen_db_count; i++) {
		if (strcmp(ca_seen_dbs[i], dir) == 0)
			return 0;
	}
	if (ca_seen_db_count < CA_MAX_SEEN_DBS)
		snprintf(ca_seen_dbs[ca_seen_db_count++], PATH_MAX, "%s", dir);
	return 1;
}

/* Nickname the proxy CA is stored under, used to add it and to tell whether a
 * database already holds it */
#define CA_NSS_NICKNAME "eptracer proxy CA"

/*
 * ca_certutil
 *
 * Description:
 * Runs certutil with the given arguments, as the invoking user so the profile
 * files are not left root-owned, with its output silenced.
 *
 * Params:
 * char *const argv[]: certutil argument vector, argv[0] == "certutil".
 *
 * Return:
 * certutil's exit status, 127 when it is not installed, -1 when it could not be
 * run at all.
 * */
static int ca_certutil(char *const argv[])
{
	pid_t pid = 0;
	int status = 0;

	pid = fork();
	if (pid < 0) {
		log_error("[!] Cannot fork to run certutil: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		int devnull = -1;

		/* Touch the database as its owner, not as root, so the profile
		 * files stay the user's and are not left root-owned behind us */
		if (drop_to_target_user() < 0)
			_exit(126);

		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execvp("certutil", argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/*
 * ca_run_certutil
 *
 * Description:
 * Makes sure the proxy CA is trusted in an NSS database, idempotently: a CA
 * already present is left as is, so neither a second detection nor a re-run
 * raises a duplicate-nickname error. The database is addressed as sql:<dir>,
 * the modern cert9.db layout.
 *
 * Params:
 * const char *db_dir: directory holding cert9.db.
 * const char *ca_file: PEM file with the proxy CA.
 *
 * Return:
 * 0 when the CA was added, 1 when it was already there, -1 on failure.
 * */
static int ca_run_certutil(const char *db_dir, const char *ca_file)
{
	char db_arg[PATH_MAX + 8];
	int rc = 0;

	snprintf(db_arg, sizeof(db_arg), "sql:%s", db_dir);

	/* Already trusted? Then there is nothing to do, and nothing to warn about */
	{
		char *check[] = { "certutil", "-L", "-d", db_arg,
				  "-n", CA_NSS_NICKNAME, NULL };

		if (ca_certutil(check) == 0)
			return 1;
	}

	{
		char *add[] = { "certutil", "-A", "-d", db_arg,
				"-n", CA_NSS_NICKNAME, "-t", "C,,",
				"-i", (char *)ca_file, NULL };
		int rv = ca_certutil(add);

		if (rv == 127) {
			log_error("[!] certutil not found: install libnss3-tools to let "
				  "ePtracer trust the proxy CA in NSS databases");
			return -1;
		}
		rc = (rv == 0) ? 0 : -1;
	}

	return rc;
}

/*
 * ca_import_into_dir
 *
 * Description:
 * Imports the proxy CA into one NSS database directory, once, logging the
 * outcome. Shared by the proactive seeding done before a spawned process starts
 * and the reactive import triggered by a process opening its database.
 *
 * Params:
 * const char *dir: directory holding cert9.db.
 * const char *who: what to name in the log (the process, or "the spawned process").
 * */
static void ca_import_into_dir(const char *dir, const char *who)
{
	const char *ca_file = NULL;
	int rc = 0;

	if (!dir || !dir[0] || strcmp(dir, ".") == 0)
		return;

	/* Seed and detection can both reach the same database; do it once */
	if (!ca_db_first_seen(dir))
		return;

	ca_file = http_ca_proxy_ca_file(ca_intercept, ca_proxy_ca);
	if (!ca_file) {
		log_error("[!] No proxy CA available to import into the NSS database %s", dir);
		return;
	}

	rc = ca_run_certutil(dir, ca_file);
	if (rc == 0)
		log_info("[+] Proxy CA imported into the NSS database of %s at %s", who, dir);
	else if (rc == 1)
		log_debug("[?] Proxy CA already trusted in the NSS database at %s", dir);
	else
		log_error("[!] Could not import the proxy CA into the NSS database %s", dir);
}

/*
 * ca_import_nss
 *
 * Description:
 * Reactive import: a process was seen opening an NSS database, so the proxy CA
 * is added to it. The directory is the directory of the opened file (cert9.db
 * and the rest live together), so no profile location is assumed.
 *
 * Params:
 * const char *db_path: the NSS file the process opened.
 * const char *comm: its command name, for logging.
 * */
static void ca_import_nss(const char *db_path, const char *comm)
{
	char copy[PATH_MAX];

	/* A relative path is relative to the process' working directory, not
	 * ours: resolving it here would import into an unrelated database */
	if (db_path[0] != '/') {
		log_debug("[?] %s opened the NSS database %s by a relative path, not importing",
			  comm, db_path);
		return;
	}

	snprintf(copy, sizeof(copy), "%s", db_path);
	ca_import_into_dir(dirname(copy), comm);
}

/*
 * ca_preseed_nss
 *
 * Description:
 * Proactive import, done before a spawned process is released: the reactive
 * path cannot win the race against an application that reads its trust store and
 * completes a handshake within milliseconds of opening it, so for a spawned
 * process — whose user, and therefore home, is known — the proxy CA is placed in
 * the well known Chromium/Electron NSS database (~/.pki/nssdb) up front, where it
 * is trusted on the very first connection. Only when that database already
 * exists: a binary that does not use NSS never reads it, so nothing is created
 * for it. Other databases, and attached processes, are still covered reactively.
 * */
/*
 * ca_seed_if_present
 *
 * Description:
 * Seeds one candidate NSS database directory, when it holds a cert9.db.
 * */
static void ca_seed_if_present(const char *dir)
{
	char probe[PATH_MAX];

	snprintf(probe, sizeof(probe), "%s/cert9.db", dir);
	if (access(probe, F_OK) == 0)
		ca_import_into_dir(dir, "the spawned process");
}

/*
 * ca_snap_name
 *
 * Description:
 * Tells whether the spawned program is a snap, and which one. A snap does not
 * use the user's home: its HOME is ~/snap/<name>/<revision>, so its NSS database
 * is ~/snap/<name>/current/.pki/nssdb. Both the /snap/bin/<name> launcher and a
 * path inside /snap/<name>/ are recognized.
 *
 * Params:
 * const char *program: the -p command line.
 * char *out, size_t out_size: receive the snap name.
 *
 * Return:
 * 0 when the program is a snap, -1 otherwise.
 * */
static int ca_snap_name(const char *program, char *out, size_t out_size)
{
	char first[PATH_MAX];
	const char *space = NULL, *rest = NULL, *slash = NULL;
	size_t len = 0;

	if (!program || !program[0])
		return -1;

	space = strchr(program, ' ');
	len = space ? (size_t)(space - program) : strlen(program);
	if (len == 0 || len >= sizeof(first))
		return -1;
	memcpy(first, program, len);
	first[len] = '\0';

	if (strncmp(first, "/snap/bin/", 10) == 0) {
		rest = first + 10;
	} else if (strncmp(first, "/snap/", 6) == 0) {
		rest = first + 6;
	} else {
		return -1;
	}

	/* "slack", "slack.foo" (an app of the snap) or "slack/260/usr/..." */
	slash = strchr(rest, '/');
	len = slash ? (size_t)(slash - rest) : strlen(rest);
	{
		const char *dot = memchr(rest, '.', len);

		if (dot)
			len = (size_t)(dot - rest);
	}
	if (len == 0 || len >= out_size)
		return -1;
	memcpy(out, rest, len);
	out[len] = '\0';
	return 0;
}

void ca_preseed_nss(const char *intercept, const char *proxy_ca, const char *program)
{
	char dir[PATH_MAX], snap[256];
	const char *home = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	char name[256] = {0};

	ca_intercept = intercept;
	ca_proxy_ca = proxy_ca;

	/* The spawned process runs as the invoking user: seed that user's home,
	 * not root's, which is where the application will look */
	if (target_user_ids(&uid, &gid, name, sizeof(name)) == 0) {
		struct passwd *pw = getpwuid(uid);

		home = pw ? pw->pw_dir : NULL;
	}
	if (!home || !home[0])
		home = getenv("HOME");
	if (!home || !home[0])
		return;

	/* A snap keeps its own home, and its own NSS database, under ~/snap */
	if (ca_snap_name(program, snap, sizeof(snap)) == 0) {
		snprintf(dir, sizeof(dir), "%s/snap/%s/current/.pki/nssdb", home, snap);
		ca_seed_if_present(dir);
		return;
	}

	snprintf(dir, sizeof(dir), "%s/.pki/nssdb", home);
	ca_seed_if_present(dir);
}

/*
 * ca_detect_event_handler
 *
 * Description:
 * Ring buffer callback: classifies the trust mechanism of the process, reports
 * it once, and triggers the NSS import for the class that allows it.
 * */
static int ca_detect_event_handler(void *ctx, void *data, size_t size)
{
	const struct ca_open_event_t *ev = data;

	(void)ctx;
	if (size < sizeof(*ev))
		return 0;

	if (ev->kind == CA_STORE_NSS_DB) {
		if (ca_pid_first_seen(ev->pid))
			log_info("[?] %s (pid %u) trusts an NSS database, not the "
				 "environment: SSL_CERT_FILE has no effect on it",
				 ev->comm, ev->pid);
		if (ca_do_import)
			ca_import_nss(ev->path, ev->comm);
	} else if (ev->kind == CA_STORE_PEM_BUNDLE) {
		if (ca_pid_first_seen(ev->pid))
			log_info("[?] %s (pid %u) reads the on-disk CA bundle %s: "
				 "SSL_CERT_FILE trust applies to it (spawned process only)",
				 ev->comm, ev->pid, ev->path);
	}
	return 0;
}

/*
 * ca_detect_enable
 *
 * Description:
 * Turns the kernel-side openat capture on. Until this is pushed the probes bail
 * out immediately, so detection costs nothing when interception is not used.
 * */
static int ca_detect_enable(struct eptracer_bpf *skel)
{
	struct ca_detect_config_t cfg = { .enabled = 1 };
	__u32 key = 0;

	return bpf_map_update_elem(bpf_map__fd(skel->maps.ca_detect_config_map),
				   &key, &cfg, BPF_ANY);
}

/*
 * ca_detect_tracer
 *
 * Description:
 * Thread entry point: attaches the open()/openat() probes, enables detection and
 * polls the cert-store opens until ePtracer is asked to stop.
 *
 * Params:
 * void *ca_detect_arguments: struct ca_detect_args.
 * */
void *ca_detect_tracer(void *ca_detect_arguments)
{
	struct ca_detect_args *arguments = (struct ca_detect_args *)ca_detect_arguments;
	struct eptracer_bpf *skel = arguments->skel;
	struct bpf_program *progs[2];
	int ret = 0, i = 0;

	ca_do_import = arguments->import;
	ca_intercept = arguments->intercept;
	ca_proxy_ca = arguments->proxy_ca;

	progs[0] = skel->progs.trace_openat_enter;
	progs[1] = skel->progs.trace_open_enter;

	for (i = 0; i < 2; i++) {
		struct bpf_link *link = bpf_program__attach(progs[i]);

		if (!link) {
			log_debug("[?] Trust-store detection probe not attached: %s",
				  strerror(errno));
			continue;
		}
		ca_links[ca_link_count++] = link;
	}
	/* no syscalls/ tracepoints (CONFIG_FTRACE_SYSCALLS off, Android GKI):
	 * the same probe over raw_syscalls */
	if (ca_link_count == 0) {
		struct bpf_link *link = bpf_program__attach(skel->progs.trace_raw_open_enter);

		if (link)
			ca_links[ca_link_count++] = link;
		else
			log_error("[!] Failed to attach the trust-store detection probe: %s",
				  strerror(errno));
	}

	if (ca_link_count == 0) {
		log_error("[!] Trust-store detection is off: no open probe could be attached");
		return NULL;
	}

	if (ca_detect_enable(skel) < 0) {
		log_error("[!] Failed to switch trust-store detection on");
		return NULL;
	}

	ca_ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.ca_rb_map),
				       ca_detect_event_handler, NULL, NULL);
	if (!ca_ring_buf) {
		log_error("[!] Error creating the trust-store detection ring buffer");
		return NULL;
	}

	log_debug("[+] Trust-store detection running%s", ca_do_import ?
		  " (NSS databases will be trusted automatically)" : "");
	ca_detect_ready = 1;

	while (!stop_requested && (ret = ring_buffer__poll(ca_ring_buf, 200)) >= 0)
		;

	return NULL;
}
