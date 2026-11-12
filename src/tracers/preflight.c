/*
 * preflight.c - `eptracer --check`: can this machine run ePtracer?
 *
 * The answer depends on the kernel, not on the distribution or the Android
 * release: ePtracer needs BPF ring buffers (5.8), BTF for CO-RE and tp_btf, and
 * the cgroup sock_addr hooks for -I. The support floor is 5.10, the first LTS
 * carrying all of them (and the GKI branch of Android 12).
 *
 * Feature probes alone do not settle it: a verifier can know a program type and
 * still reject a program, so every BPF program of the skeleton is also loaded
 * on its own and the failures are reported per feature. Exit status is 0 when
 * the core features load, 1 otherwise, which is what the test matrix keys on.
 */
#include <sys/stat.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>

/* Included by eptracer.c after the skeleton, log_level and libbpf_print_fn */

#define PREFLIGHT_MIN_MAJOR 5
#define PREFLIGHT_MIN_MINOR 10

enum pf_status { PF_OK, PF_WARN, PF_FAIL };

static int pf_failures;
static int pf_verbose;
static int pf_warnings;

static void pf_report(enum pf_status st, const char *what, const char *fmt, ...)
{
	static const char *const tag[] = { "  OK  ", " WARN ", " FAIL " };
	va_list ap;

	if (st == PF_FAIL)
		pf_failures++;
	else if (st == PF_WARN)
		pf_warnings++;
	printf("[%s] %-28s ", tag[st], what);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

/* libbpf is chatty on every rejected load: keep the report readable */
static int pf_silent_print(enum libbpf_print_level level, const char *format, va_list ap)
{
	(void)level;
	(void)format;
	(void)ap;
	return 0;
}

/* "ro.build.version.release=14" from /system/build.prop */
static int pf_android_prop(const char *key, char *out, size_t len)
{
	char line[256];
	size_t klen = strlen(key);
	FILE *fp = fopen("/system/build.prop", "r");
	int found = 0;

	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
			snprintf(out, len, "%s", line + klen + 1);
			out[strcspn(out, "\r\n")] = '\0';
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

static void pf_check_kernel(void)
{
	struct utsname u;
	int major = 0, minor = 0;
	char rel[64] = "", sdk[16] = "";

	if (uname(&u) != 0) {
		pf_report(PF_FAIL, "kernel", "uname: %s", strerror(errno));
		return;
	}
	sscanf(u.release, "%d.%d", &major, &minor);
	if (major > PREFLIGHT_MIN_MAJOR ||
	    (major == PREFLIGHT_MIN_MAJOR && minor >= PREFLIGHT_MIN_MINOR))
		pf_report(PF_OK, "kernel", "%s %s", u.release, u.machine);
	else
		pf_report(PF_FAIL, "kernel", "%s %s: %d.%d or newer is required",
			  u.release, u.machine, PREFLIGHT_MIN_MAJOR, PREFLIGHT_MIN_MINOR);

	if (access("/system/build.prop", F_OK) == 0) {
		pf_android_prop("ro.build.version.release", rel, sizeof(rel));
		pf_android_prop("ro.build.version.sdk", sdk, sizeof(sdk));
		pf_report(PF_OK, "platform", "Android %s (API %s)",
			  *rel ? rel : "?", *sdk ? sdk : "?");
	} else {
		pf_report(PF_OK, "platform", "Linux");
	}
}

static void pf_check_environment(void)
{
	struct stat st;

	if (geteuid() == 0)
		pf_report(PF_OK, "privileges", "running as root");
	else
		pf_report(PF_FAIL, "privileges", "euid %d: run as root (su on Android)", geteuid());

	if (stat("/sys/kernel/btf/vmlinux", &st) == 0)
		pf_report(PF_OK, "BTF", "/sys/kernel/btf/vmlinux (%lld KiB)",
			  (long long)st.st_size / 1024);
	else
		pf_report(PF_FAIL, "BTF", "/sys/kernel/btf/vmlinux missing: kernel built without CONFIG_DEBUG_INFO_BTF");

	if (access("/sys/bus/event_source/devices/uprobe/type", F_OK) == 0)
		pf_report(PF_OK, "uprobes", "uprobe PMU available");
	else
		pf_report(PF_FAIL, "uprobes", "no uprobe PMU: kernel built without CONFIG_UPROBE_EVENTS");

	if (access("/sys/kernel/tracing/events/syscalls", F_OK) == 0 ||
	    access("/sys/kernel/debug/tracing/events/syscalls", F_OK) == 0)
		pf_report(PF_OK, "syscall tracepoints", "per-syscall (CONFIG_FTRACE_SYSCALLS)");
	else
		pf_report(PF_OK, "syscall tracepoints", "raw_syscalls only (no CONFIG_FTRACE_SYSCALLS): fallback in use");

	if (access("/sys/fs/cgroup/cgroup.controllers", F_OK) == 0)
		pf_report(PF_OK, "cgroup v2", "mounted at /sys/fs/cgroup");
	else
		pf_report(PF_WARN, "cgroup v2", "not at /sys/fs/cgroup: -I/--intercept will not work");
}

static void pf_check_kernel_features(void)
{
	static const struct {
		const char *name;
		enum bpf_prog_type type;
		int core;
	} progs[] = {
		{ "prog: tracepoint",       BPF_PROG_TYPE_TRACEPOINT,      1 },
		{ "prog: kprobe/uprobe",    BPF_PROG_TYPE_KPROBE,          1 },
		{ "prog: perf_event",       BPF_PROG_TYPE_PERF_EVENT,      1 },
		{ "prog: tracing (tp_btf)", BPF_PROG_TYPE_TRACING,         1 },
		{ "prog: cgroup sock_addr", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, 0 },
	};
	int r;

	r = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL);
	if (r == 1)
		pf_report(PF_OK, "map: ringbuf", "supported");
	else
		pf_report(PF_FAIL, "map: ringbuf", "not supported (needs 5.8+)");

	for (size_t i = 0; i < sizeof(progs) / sizeof(*progs); i++) {
		r = libbpf_probe_bpf_prog_type(progs[i].type, NULL);
		if (r == 1)
			pf_report(PF_OK, progs[i].name, "supported");
		else
			pf_report(progs[i].core ? PF_FAIL : PF_WARN, progs[i].name,
				  "not supported%s", progs[i].core ? "" : " (-I unavailable)");
	}
}

/* Which ePtracer feature a BPF program serves, from its name */
static const char *pf_feature_of(const char *prog)
{
	static const struct { const char *prefix; const char *feature; } map[] = {
		{ "follow_",         "core (-F, exit tracking)" },
		{ "get_stacktrace",  "-s stack traces" },
		{ "sys_enter_",      "-S syscalls" },
		{ "probe_ssl_",      "-H TLS capture" },
		{ "probe_go_tls_",   "-H Go TLS capture" },
		{ "trace_sock_",     "-H cleartext capture" },
		{ "trace_raw_sock_", "-H cleartext capture" },
		{ "trace_raw_open",  "-I CA detection" },
		{ "trace_connect",   "-H peer tracking" },
		{ "trace_close",     "-H peer tracking" },
		{ "trace_open",      "-I CA detection" },
		{ "intercept_",      "-I interception" },
		{ "probe_tls_",      "--tls-mode splice" },
		{ "probe_hmac_",     "--tls-mode splice" },
		{ "trace_exec",      "--tls-mode splice" },
		{ "trace_dlopen",    "--tls-mode splice" },
	};

	for (size_t i = 0; i < sizeof(map) / sizeof(*map); i++)
		if (strncmp(prog, map[i].prefix, strlen(map[i].prefix)) == 0)
			return map[i].feature;
	return "?";
}

/* Load the skeleton with only `only` enabled (NULL: everything) */
static int pf_load_with(const char *only)
{
	struct eptracer_bpf *s = eptracer_bpf__open();
	struct bpf_program *p;
	int err;

	if (!s)
		return -errno;
	bpf_object__for_each_program(p, s->obj)
		bpf_program__set_autoload(p, !only || strcmp(bpf_program__name(p), only) == 0);
	err = eptracer_bpf__load(s);
	eptracer_bpf__destroy(s);
	return err;
}

static void pf_check_programs(void)
{
	struct eptracer_bpf *s;
	struct bpf_program *p;
	char names[64][64];
	int n = 0, err;

	err = pf_load_with(NULL);
	if (err == 0) {
		pf_report(PF_OK, "BPF programs", "all programs pass the verifier");
		return;
	}
	pf_report(PF_WARN, "BPF programs", "full load failed (%s), checking one by one",
		  strerror(-err));

	s = eptracer_bpf__open();
	if (!s) {
		pf_report(PF_FAIL, "BPF object", "cannot open: %s", strerror(errno));
		return;
	}
	bpf_object__for_each_program(p, s->obj)
		if (n < 64)
			snprintf(names[n++], sizeof(names[0]), "%s", bpf_program__name(p));
	eptracer_bpf__destroy(s);

	for (int i = 0; i < n; i++) {
		const char *feat = pf_feature_of(names[i]);
		int core = strncmp(feat, "core", 4) == 0;

		err = pf_load_with(names[i]);
		if (err)
			pf_report(core ? PF_FAIL : PF_WARN, names[i], "rejected (%s): %s unavailable",
				  strerror(-err), feat);
		else if (pf_verbose)
			pf_report(PF_OK, names[i], "%s", feat);
	}
}

/*
 * run_preflight
 *
 * Return:
 * 0 when ePtracer can run here, 1 otherwise.
 */
static int run_preflight(int verbose)
{
	libbpf_print_fn_t prev = libbpf_set_print(verbose ? libbpf_print_fn : pf_silent_print);

	pf_verbose = verbose;

	printf("ePtracer preflight check (minimum kernel %d.%d with BTF)\n\n",
	       PREFLIGHT_MIN_MAJOR, PREFLIGHT_MIN_MINOR);
	pf_check_kernel();
	pf_check_environment();
	if (geteuid() == 0) {
		pf_check_kernel_features();
		/* without BTF or ring buffers every program fails the same way:
		 * one line per program would only bury the cause */
		if (pf_failures == 0)
			pf_check_programs();
		else
			pf_report(PF_WARN, "BPF programs", "not loaded: the requirements above are missing");
	}
	libbpf_set_print(prev);

	printf("\n%s: %d failure(s), %d warning(s)\n",
	       pf_failures ? "NOT SUPPORTED" : "SUPPORTED", pf_failures, pf_warnings);
	return pf_failures ? 1 : 0;
}
