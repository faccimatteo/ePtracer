/*
 * TLS splice inside the interceptor — #included by tracers/http_intercept.c.
 *
 * `--tls-mode splice` changes what happens to a redirected TLS connection. The
 * default (mitm) tunnels it to the proxy, which presents its own certificate:
 * pinning refuses it. Splice instead:
 *
 *  1. resolves the keylog function of every TLS library the target uses
 *     (tracers/tls_anchor.c) and puts probe_tls_keylog on it: the session
 *     secrets reach tls_secret_rb as the library derives them;
 *  2. connects the redirected connection to the server the app asked for and
 *     lets the handshake through untouched (the real certificate, so pinning
 *     holds);
 *  3. runs it through the splice bridge (include/splice_bridge.h): decrypted
 *     with those secrets, every request goes to the proxy, comes back to
 *     ePtracer as the proxy's upstream, and is sealed into the app's own session
 *     towards the server — at most once.
 *
 * The proxy has to use ePtracer as its upstream proxy (Burp: Settings → Network
 * → Connections → Upstream proxy servers, Caido: Upstream Proxies), on
 * --bridge-port. Nothing has to be trusted by the app.
 */

#include "tls_anchor.h"
#include "tls_keys.h"
#include "splice_bridge.h"

#include <dirent.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#include "tls_record.c"
#include "tls_keys.c"
#include "tls_splice.c"
#include "tls_anchor.c"
#include "http1_frame.c"
#include "proxy_bridge.c"
#include "splice_bridge.c"

#define SPLICE_DEFAULT_BRIDGE_PORT 8082
#define SPLICE_DEFAULT_HOLD_MS     200
/* Probes placed: keylog functions, SHA-2 block functions, the load watches */
#define SPLICE_MAX_LINKS           256
/* exec/dlopen events waiting for the process's new objects to be probed */
#define SPLICE_MAX_EXECS           64

static int splice_requested = 0;      /* --tls-mode splice */
static int splice_running = 0;        /* the bridge is up */
static int splice_strict = 0;
static int splice_hold_ms = SPLICE_DEFAULT_HOLD_MS;
static int splice_bridge_listen_port = SPLICE_DEFAULT_BRIDGE_PORT;
static char splice_proxy_ca[sizeof(((struct splice_bridge_cfg *)0)->proxy_ca)];

static struct ring_buffer *splice_key_rb = NULL;
static pthread_mutex_t splice_key_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t splice_key_thread;
static volatile int splice_key_running = 0;
static struct bpf_link *splice_links[SPLICE_MAX_LINKS];
static int splice_link_count = 0;
static struct eptracer_bpf *splice_skel = NULL;
/* Objects already looked at, so each one is scanned once: a file, or a library
 * stored inside an APK at an offset, known by inode whatever path reached it
 * (the target's own view through /proc/<pid>/root may not be ours, e.g. from
 * a chroot). The HMAC fallback is only for what the target really runs or
 * loads: a well known library probed ahead of time gets its keylog function or
 * nothing, and its SHA-2 functions only if the target maps it later. */
struct splice_obj {
	dev_t    dev;
	ino_t    ino;
	uint64_t elf_off;    /* where the ELF image starts in the file */
	int      tls;        /* carries the TLS 1.3 labels */
	int      keylog;     /* keylog function probed */
	int      hmac_done;  /* HMAC fallback considered */
};
static struct splice_obj *splice_seen = NULL;
static size_t splice_nseen = 0, splice_seen_cap = 0;
/* pids reported by trace_exec/trace_dlopen, filled under splice_key_lock. Each
 * one is stopped until its new objects are probed and it gets SIGCONT. */
static pid_t splice_execs[SPLICE_MAX_EXECS];
static int splice_nexecs = 0;

static void splice_probe_maps(pid_t pid);

/*
 * http_intercept_use_splice
 *
 * Description:
 * Asks the interceptor to splice TLS instead of tunnelling it to a MITM proxy.
 * Must be called before http_intercept_start().
 *
 * Params:
 * int strict: never let client data the proxy could not see reach the server.
 * int hold_ms: how long a client record waits for its key (<= 0: default).
 * int bridge_port: port the proxy uses as its upstream (<= 0: default).
 * const char *proxy_ca: proxy CA to verify the proxy against, NULL or "" to skip.
 * */
void http_intercept_use_splice(int strict, int hold_ms, int bridge_port, const char *proxy_ca)
{
	splice_requested = 1;
	splice_strict = strict;
	splice_hold_ms = hold_ms > 0 ? hold_ms : SPLICE_DEFAULT_HOLD_MS;
	splice_bridge_listen_port = bridge_port > 0 ? bridge_port : SPLICE_DEFAULT_BRIDGE_PORT;
	snprintf(splice_proxy_ca, sizeof(splice_proxy_ca), "%s", proxy_ca ? proxy_ca : "");
}

/* ---- key capture ------------------------------------------------------- */

static int splice_exec_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size >= sizeof(__u32) && splice_nexecs < SPLICE_MAX_EXECS)
		splice_execs[splice_nexecs++] = (pid_t)*(const __u32 *)data;
	return 0;
}

static int splice_key_event(void *ctx, void *data, size_t size)
{
	const struct tls_secret_event_t *ev = data;
	(void)ctx;

	if (size < sizeof(*ev))
		return 0;
	if (tls_keys_add(ev) == 0)
		log_debug("[k] %s captured for pid %u (%u bytes)", ev->label_name, ev->pid,
			  ev->secret_len);
	return 0;
}

/* Drain whatever key events are pending, now. Called by the splice right before
 * it looks keys up, so a secret already on the ring is never missed. */
static void splice_drain_keys(void *user)
{
	(void)user;
	pthread_mutex_lock(&splice_key_lock);
	if (splice_key_rb)
		ring_buffer__consume(splice_key_rb);
	pthread_mutex_unlock(&splice_key_lock);
}

static void *splice_key_loop(void *unused)
{
	int efd = ring_buffer__epoll_fd(splice_key_rb);
	(void)unused;

	while (splice_key_running && !stop_requested) {
		struct epoll_event ev;
		pid_t execs[SPLICE_MAX_EXECS];
		int n = 0, i = 0;

		/* wait outside the lock, consume under it: libbpf's ring buffer
		 * manager is not meant to be used from two threads at once */
		epoll_wait(efd, &ev, 1, 200);
		pthread_mutex_lock(&splice_key_lock);
		if (splice_key_rb)
			ring_buffer__consume(splice_key_rb);
		n = splice_nexecs;
		memcpy(execs, splice_execs, sizeof(*execs) * (size_t)n);
		splice_nexecs = 0;
		pthread_mutex_unlock(&splice_key_lock);

		/* scanning a binary takes a while: never with the lock held, the
		 * splice is waiting on it for keys */
		for (i = 0; i < n; i++) {
			splice_probe_maps(execs[i]);
			kill(execs[i], SIGCONT);
		}
	}
	return NULL;
}

/* Put one key probe at off in path. 0, or -1 when it cannot be placed. */
static int splice_attach(struct bpf_program *prog, const char *path, uint64_t off)
{
	struct bpf_link *link = NULL;

	if (splice_link_count == SPLICE_MAX_LINKS)
		return -1;
	/* system wide and filtered in kernel space, like the other TLS probes */
	link = bpf_program__attach_uprobe(prog, false, -1, path, (size_t)off);
	if (!link) {
		log_error("[!] Cannot attach a key probe to %s+0x%llx: %s", path,
			  (unsigned long long)off, strerror(errno));
		return -1;
	}
	splice_links[splice_link_count++] = link;
	return 0;
}

/* How an object is named in the log: its path, and the offset for an APK entry */
static void splice_obj_name(char *out, size_t cap, const char *name, uint64_t elf_off)
{
	if (elf_off)
		snprintf(out, cap, "%s!0x%llx", name, (unsigned long long)elf_off);
	else
		snprintf(out, cap, "%s", name);
}

/*
 * OpenSSL builds where ssl_log_secret() was inlined (Ubuntu 22.04's 3.0.2)
 * check for a keylog callback in the caller, before nss_keylog_int() is even
 * called: the anchor is right, but it only fires in a process that installed a
 * callback. The secrets still go through HMAC as keys in libcrypto, which ships
 * next to libssl: probe its SHA-2 block functions too.
 */
static void splice_attach_crypto_hmac(const char *access)
{
	static char done[8][PATH_MAX];
	static int ndone;
	char pattern[PATH_MAX + 32];
	const char *slash = strrchr(access, '/');
	struct tls_sha_hit sha[32];
	glob_t gl;

	if (!slash)
		return;
	snprintf(pattern, sizeof(pattern), "%.*s/libcrypto.so*", (int)(slash - access), access);
	if (glob(pattern, 0, NULL, &gl) != 0)
		return;
	for (size_t k = 0; k < gl.gl_pathc; k++) {
		char real[PATH_MAX];
		int seen = 0, placed = 0, n;

		if (!realpath(gl.gl_pathv[k], real))
			continue;
		for (int i = 0; i < ndone; i++)
			seen |= !strcmp(done[i], real);
		if (seen)
			continue;
		n = tls_anchor_find_hmac_crypto(gl.gl_pathv[k], sha, sizeof(sha) / sizeof(*sha));
		for (int j = 0; j < n; j++)
			placed += splice_attach(sha[j].bits == 256 ? splice_skel->progs.probe_hmac_sha256
								   : splice_skel->progs.probe_hmac_sha512,
						gl.gl_pathv[k], sha[j].file_off) == 0;
		if (ndone < 8)
			snprintf(done[ndone++], sizeof(done[0]), "%s", real);
		if (placed)
			log_info("[+] Keys of %s also from its HMAC key setup (%d SHA-2 functions): "
				 "its keylog function only runs with a callback installed",
				 gl.gl_pathv[k], placed);
		break;
	}
	globfree(&gl);
}

static int splice_attach_keylog(const char *access, const char *name, uint64_t elf_off)
{
	struct tls_anchor_hit hit;
	char labels[256] = "", what[PATH_MAX + 32];
	unsigned i = 0;

	if (tls_anchor_find_at(access, elf_off, &hit) != 0)
		return 0;
	for (i = 0; i < tls_anchor_label_count(); i++)
		if (hit.label_mask & (1u << i)) {
			if (labels[0])
				strncat(labels, ", ", sizeof(labels) - strlen(labels) - 1);
			strncat(labels, tls_anchor_label_name(i), sizeof(labels) - strlen(labels) - 1);
		}
	if (splice_attach(hit.abi == TLS_KEYLOG_ABI_NSS_INT ? splice_skel->progs.probe_tls_keylog_nss
							     : splice_skel->progs.probe_tls_keylog,
			  access, elf_off + hit.file_off) != 0)
		return 0;
	splice_obj_name(what, sizeof(what), name, elf_off);
	log_info("[+] Keylog function of %s at +0x%llx (anchored by %s%s)", what,
		 (unsigned long long)hit.file_off, labels,
		 hit.abi == TLS_KEYLOG_ABI_NSS_INT ? "; nss_keylog_int arguments" : "");
	if (hit.abi == TLS_KEYLOG_ABI_NSS_INT && elf_off == 0)
		splice_attach_crypto_hmac(access);
	return 1;
}

/* No keylog function (rustls, an OpenSSL built without one): the secrets are
 * caught as HMAC keys inside SHA-2 */
static void splice_attach_hmac(const char *access, const char *name, uint64_t elf_off)
{
	struct tls_sha_hit sha[32];
	char what[PATH_MAX + 32];
	int n = tls_anchor_find_hmac_at(access, elf_off, sha, sizeof(sha) / sizeof(*sha)), placed = 0;

	for (int k = 0; k < n; k++)
		placed += splice_attach(sha[k].bits == 256 ? splice_skel->progs.probe_hmac_sha256 :
				       splice_skel->progs.probe_hmac_sha512, access,
				       elf_off + sha[k].file_off) == 0;
	splice_obj_name(what, sizeof(what), name, elf_off);
	if (placed)
		log_info("[+] Keys of %s from its HMAC key setup (%d SHA-2 functions)", what, placed);
}

/* A TLS 1.3 stack, whatever it is, carries this derivation label: anything
 * without it is not worth an ELF scan (a process maps hundreds of files) */
static int splice_maybe_tls(int fd, size_t size, uint64_t elf_off)
{
	int found = 0;
	void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map != MAP_FAILED) {
		found = memmem((char *)map + elf_off, size - (size_t)elf_off, "c ap traffic", 12) != NULL;
		munmap(map, size);
	}
	return found;
}

/*
 * Probe an object once. access: the path to open (through /proc/<pid>/root when
 * it comes from a process); name: its path as the process sees it, for the log;
 * used: the target runs or maps it, rather than a well known library probed
 * ahead of time.
 */
static void splice_probe_object(const char *access, const char *name, uint64_t elf_off, int used)
{
	struct splice_obj *o = NULL;
	struct stat st;
	int fd;

	if (!splice_skel || (fd = open(access, O_RDONLY | O_CLOEXEC)) < 0)
		return;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size <= elf_off) {
		close(fd);
		return;
	}
	for (size_t i = 0; i < splice_nseen && !o; i++)
		if (splice_seen[i].dev == st.st_dev && splice_seen[i].ino == st.st_ino &&
		    splice_seen[i].elf_off == elf_off)
			o = &splice_seen[i];
	if (!o) {
		if (splice_nseen == splice_seen_cap) {
			size_t cap = splice_seen_cap ? splice_seen_cap * 2 : 64;
			struct splice_obj *grown = realloc(splice_seen, cap * sizeof(*grown));
			if (!grown) {
				close(fd);
				return;
			}
			splice_seen = grown;
			splice_seen_cap = cap;
		}
		o = &splice_seen[splice_nseen++];
		memset(o, 0, sizeof(*o));
		o->dev = st.st_dev;
		o->ino = st.st_ino;
		o->elf_off = elf_off;
		o->tls = splice_maybe_tls(fd, (size_t)st.st_size, elf_off);
		if (o->tls)
			o->keylog = splice_attach_keylog(access, name, elf_off);
	}
	close(fd);
	if (o->tls && !o->keylog && used && !o->hmac_done) {
		o->hmac_done = 1;
		splice_attach_hmac(access, name, elf_off);
	}
}

/* Does an ELF image start at off in this file? */
static int splice_elf_at(const char *access, uint64_t off)
{
	unsigned char magic[4];
	int fd = open(access, O_RDONLY | O_CLOEXEC), ok = 0;
	if (fd < 0)
		return 0;
	ok = pread(fd, magic, sizeof(magic), (off_t)off) == 4 && !memcmp(magic, "\177ELF", 4);
	close(fd);
	return ok;
}

/*
 * Every executable file a process maps: after an exec its new program, after a
 * dlopen the library (and what it pulled in). A library loaded straight from an
 * APK (extractNativeLibs=false) shows up as base.apk at the offset of its entry:
 * the mapping whose offset holds an ELF header is where it starts.
 */
static void splice_probe_maps(pid_t pid)
{
	char path[64], line[PATH_MAX + 128];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char perms[8] = "", *file = strchr(line, '/'), access[PATH_MAX + 64];
		unsigned long long off = 0;
		if (!file || sscanf(line, "%*s %7s %llx", perms, &off) != 2)
			continue;
		file[strcspn(file, "\n")] = '\0';
		snprintf(access, sizeof(access), "/proc/%d/root%s", pid, file);
		size_t len = strlen(file);
		if (len > 4 && !strcmp(file + len - 4, ".apk")) {
			if (splice_elf_at(access, off))
				splice_probe_object(access, file, off, 1);
		} else if (strchr(perms, 'x')) {
			splice_probe_object(access, file, 0, 1);
		}
	}
	fclose(f);
}

/* --package/--uid: what the processes of the app already run */
void splice_capture_uid(uid_t uid)
{
	DIR *d = opendir("/proc");
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d))) {
		char status[64], line[256];
		unsigned real = 0;
		int match = 0;
		FILE *f;
		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		snprintf(status, sizeof(status), "/proc/%s/status", e->d_name);
		if (!(f = fopen(status, "re")))
			continue;
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "Uid: %u", &real) == 1) {
				match = real == uid;
				break;
			}
		fclose(f);
		if (match)
			splice_probe_maps((pid_t)atoi(e->d_name));
	}
	closedir(d);
}

/*
 * splice_capture_start
 *
 * Description:
 * Installs the key probe on every TLS library the target maps (the same
 * discovery as the HTTP tracer, so --ssl-lib applies too) and on its executable
 * (statically linked TLS), then starts consuming tls_secret_rb.
 *
 * Return:
 * Number of objects probed now. Programs the target executes later (a launcher
 * script, an updater, the real binary) are probed as they start, from
 * trace_exec: 0 here is normal for a target that is only a launcher.
 * */
int splice_capture_start(struct eptracer_bpf *skel, pid_t pid, const char *program,
			 const char *lib_spec)
{
	struct ssl_candidate libs[MAX_SSL_LIBS];
	char exe[PATH_MAX] = "";
	struct bpf_link *watch = NULL;
	int lib_count = 0, i = 0, before = splice_link_count;

	splice_skel = skel;
	memset(libs, 0, sizeof(libs));
	if (collect_user_ssl_libs(lib_spec, libs, &lib_count) == 0) {
		collect_mapped_ssl_libs(pid, libs, &lib_count);
		collect_wellknown_ssl_libs(libs, &lib_count);
	}
	for (i = 0; i < lib_count; i++)
		splice_probe_object(libs[i].path, libs[i].path, 0, 0);
	if (resolve_target_exe(pid, program, exe, sizeof(exe)) == 0)
		splice_probe_object(exe, exe, 0, 1);
	/* Android: Conscrypt, the BoringSSL behind OkHttp, Retrofit and the whole
	 * Java networking stack, mapped by every app */
	{
		glob_t gl;
		if (glob("/apex/com.android.conscrypt/lib*/libssl.so", 0, NULL, &gl) == 0) {
			for (size_t k = 0; k < gl.gl_pathc; k++)
				splice_probe_object(gl.gl_pathv[k], gl.gl_pathv[k], 0, 0);
			globfree(&gl);
		}
	}
	if (pid > 0)
		splice_probe_maps(pid);

	splice_key_rb = ring_buffer__new(bpf_map__fd(skel->maps.tls_secret_rb),
					 splice_key_event, NULL, NULL);
	if (!splice_key_rb ||
	    ring_buffer__add(splice_key_rb, bpf_map__fd(skel->maps.exec_rb),
			     splice_exec_event, NULL) != 0) {
		log_error("[!] Cannot read the TLS key ring buffers");
		return 0;
	}
	/* programs the target executes later, and libraries it loads, are probed
	 * as they arrive (dlopen lives in libc since glibc 2.34) */
	watch = bpf_program__attach(skel->progs.trace_exec);
	if (watch)
		splice_links[splice_link_count++] = watch;
	{
		/* where dlopen ends up: glibc's libc, Android's linker (System.loadLibrary
		 * goes through android_dlopen_ext) */
		static const struct { const char *glob, *func; } loaders[] = {
			{ "/usr/lib/*/libc.so.6", "dlopen" },
			{ "/lib64/libc.so.6", "dlopen" },
			{ "/apex/com.android.runtime/bin/linker64", "__loader_dlopen" },
			{ "/apex/com.android.runtime/bin/linker64", "__loader_android_dlopen_ext" },
		};
		char done[8][PATH_MAX + 64];
		int ndone = 0;
		for (size_t g = 0; g < sizeof(loaders) / sizeof(*loaders); g++) {
			glob_t gl;
			if (glob(loaders[g].glob, 0, NULL, &gl) != 0)
				continue;
			for (size_t k = 0; k < gl.gl_pathc && ndone < 8; k++) {
				char real[PATH_MAX], key[PATH_MAX + 64];
				int dup = 0;
				if (!realpath(gl.gl_pathv[k], real))
					continue;
				snprintf(key, sizeof(key), "%s:%s", real, loaders[g].func);
				for (int d = 0; d < ndone; d++)
					dup |= strcmp(done[d], key) == 0;
				if (dup)
					continue;
				snprintf(done[ndone++], sizeof(done[0]), "%s", key);
				LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = loaders[g].func, .retprobe = true);
				struct bpf_link *l = bpf_program__attach_uprobe_opts(skel->progs.trace_dlopen,
										     -1, real, 0, &uo);
				if (l && splice_link_count < SPLICE_MAX_LINKS)
					splice_links[splice_link_count++] = l;
			}
			globfree(&gl);
		}
	}
	splice_key_running = 1;
	if (pthread_create(&splice_key_thread, NULL, splice_key_loop, NULL) != 0) {
		splice_key_running = 0;
		return 0;
	}
	return splice_link_count - before - (watch ? 1 : 0);
}

/* ---- the interceptor side ---------------------------------------------- */

static void splice_log(void *user, const char *line)
{
	(void)user;
	log_info("%s", line);
}

/* Called by http_intercept_start() once the proxy address is known */
static int splice_start_bridge(void)
{
	struct splice_bridge_cfg cfg;

	if (intercept_direct) {
		log_error("[!] --tls-mode splice needs a proxy: 'direct' has nobody to "
			  "show the traffic to");
		return -1;
	}

	memset(&cfg, 0, sizeof(cfg));
	snprintf(cfg.proxy_host, sizeof(cfg.proxy_host), "%s", intercept_upstream_host);
	cfg.proxy_port = intercept_upstream_port;
	snprintf(cfg.proxy_ca, sizeof(cfg.proxy_ca), "%s", splice_proxy_ca);
	cfg.upstream_port = splice_bridge_listen_port;
	cfg.strict = splice_strict;
	cfg.hold_ms = splice_hold_ms;
	cfg.need_keys = splice_drain_keys;
	cfg.log = splice_log;

	if (splice_bridge_start(&cfg) != 0) {
		log_error("[!] TLS splice: cannot listen on 127.0.0.1:%d for the proxy",
			  splice_bridge_listen_port);
		return -1;
	}
	splice_running = 1;
	log_info("[+] TLS splice: set 127.0.0.1:%d as the upstream proxy of %s:%d "
		 "(Burp: Settings > Network > Connections > Upstream proxy servers)",
		 splice_bridge_upstream_port(), intercept_upstream_host, intercept_upstream_port);
	if (splice_strict)
		log_info("[+] TLS splice is strict: what the proxy cannot see never reaches "
			 "the server");
	return 0;
}

/*
 * One redirected TLS connection: straight to the server the app asked for, the
 * handshake untouched, the rest through the bridge.
 */
static void splice_session(struct intercept_session *session, const char *literal,
			   int port, const char *authority)
{
	int server_fd = intercept_dial(literal, port);
	int client_fd = -1;

	if (server_fd < 0) {
		intercept_failed++;
		log_error("[!] Splice of %s:%d: the server cannot be reached", authority, port);
		return;
	}
	/* the bridge closes its fds; the session thread owns the original one */
	client_fd = dup(session->client_fd);
	if (client_fd < 0) {
		close(server_fd);
		return;
	}
	if (splice_bridge_run_flow(client_fd, server_fd, session->orig.pid, authority, port) != 0)
		log_info("[-] Splice of %s:%d ended with an error (see above)", authority, port);
}

static void splice_stop(void)
{
	int i = 0;

	/* idempotent and safe even if the bridge only half-started */
	splice_bridge_stop();
	splice_running = 0;
	/* detach first: from here no exec can stop a process any more */
	for (i = 0; i < splice_link_count; i++)
		bpf_link__destroy(splice_links[i]);
	splice_link_count = 0;
	if (splice_key_running) {
		splice_key_running = 0;
		pthread_join(splice_key_thread, NULL);
	}
	pthread_mutex_lock(&splice_key_lock);
	/* and never leave one stopped behind */
	if (splice_key_rb)
		ring_buffer__consume(splice_key_rb);
	for (i = 0; i < splice_nexecs; i++)
		kill(splice_execs[i], SIGCONT);
	splice_nexecs = 0;
	ring_buffer__free(splice_key_rb);
	splice_key_rb = NULL;
	pthread_mutex_unlock(&splice_key_lock);
}
