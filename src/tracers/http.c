#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Maximum number of shared objects we attach the SSL uprobes to */
#define MAX_SSL_LIBS        16
/* Executables and libraries looked at for TLS probes over the whole run: the
 * target ones, plus those of its children when the process tree is followed */
#define MAX_HOOKED_OBJECTS  128
/* One uprobe + one uretprobe for each of SSL_read/SSL_write/_ex, per library,
 * and the entry and return probes of Go executables */
#define MAX_HTTP_LINKS      2048
/* How often the memory maps of followed child processes are looked at again */
#define HTTP_RESCAN_MS      1000
/* Body bytes printed as text before truncating the output */
#define HTTP_BODY_PRINT_MAX 2048
/* Bytes shown when a payload is binary */
#define HTTP_HEXDUMP_MAX    256

static struct ring_buffer *http_ring_buf = NULL;
static struct bpf_link *http_links[MAX_HTTP_LINKS];
static int http_link_count = 0;
/* CLOCK_REALTIME - CLOCK_MONOTONIC, to turn bpf_ktime_get_ns() into wall time */
static __s64 http_clock_offset_ns = 0;
/* Raised once every probe is installed, read by main() before releasing a
 * process spawned with -p */
static volatile int http_tracer_ready = 0;
/* Show every captured chunk as it arrives instead of reassembling messages */
static int http_chunk_view = 0;
/* Every library and executable already considered for TLS probes, hooked or
 * not, so that a rescan never attaches the same probe twice */
static char *http_hooked_objects[MAX_HOOKED_OBJECTS];
static int http_hooked_count = 0;

/*
 * The TLS stacks ePtracer knows how to read the plaintext from.
 *
 * There is no generic hook for this. TLS is a userspace concern: the boundary
 * between plaintext and ciphertext only exists inside a specific function of a
 * specific library, and eBPF can hook nothing it cannot name — no kernel event
 * corresponds to "the request, before it was encrypted". (The one exception is
 * kTLS, where the kernel does the crypto and the plaintext really does cross
 * the syscall boundary: those processes are already covered by the socket
 * tracepoints.)
 *
 * Covering "every process" therefore means covering the ABIs one at a time,
 * which is cheap: every one of these libraries moves data with the very same
 * calling shape — (handle, buffer, length), returning the byte count — so the
 * BPF programs are shared and only the symbol names differ.
 */
struct ssl_hook {
	const char *symbol;
	int is_read;
	int is_ex;      /* length reported out of band, through a size_t* argument */
};

struct tls_abi {
	const char *name;
	const char *const *hints;   /* substrings matched against the mapped paths */
	const char *const *globs;   /* well known locations, when /proc is not usable */
	const struct ssl_hook *hooks;
	size_t hook_count;
};

/* OpenSSL, and every BoringSSL fork that kept its ABI. "libssl.so" rather than
 * "libssl" on purpose: it must match libssl.so.3 without catching NSS own
 * libssl3.so, which shares nothing but the name. */
static const char *const openssl_hints[] = {
	"libssl.so",
	"boringssl",
	"conscrypt",        /* Android TLS provider */
	"libcronet",        /* Chromium network stack embedded in apps */
	"libmonochrome",    /* Android WebView / Chrome */
	"libflutter",       /* Flutter apps statically link BoringSSL */
	NULL,
};

static const char *const openssl_globs[] = {
	/* Linux distributions */
	"/lib/*/libssl.so*",
	"/usr/lib/*/libssl.so*",
	"/usr/lib64/libssl.so*",
	/* no multiarch directory: Alpine, Arch */
	"/lib/libssl.so*",
	"/usr/lib/libssl.so*",
	"/usr/local/lib/libssl.so*",
	/* Android */
	"/apex/com.android.conscrypt/lib64/libssl.so",
	"/apex/com.android.conscrypt/lib/libssl.so",
	"/system/lib64/libssl.so",
	"/system/lib/libssl.so",
	NULL,
};

static const struct ssl_hook openssl_hooks[] = {
	{ "SSL_write",    0, 0 },
	{ "SSL_read",     1, 0 },
	{ "SSL_write_ex", 0, 1 },
	{ "SSL_read_ex",  1, 1 },
};

/*
 * NSS, which is what Firefox, Thunderbird and everything Gecko use. Its TLS
 * has nothing to do with the OpenSSL ABI: NSS layers PRFileDescs, the SSL
 * layer sits above the TCP one, and the application reads through NSPR. So
 * PR_Read() on an SSL socket already returns decrypted bytes, and PR_Write()
 * is handed the plaintext.
 *
 * Only the *outermost* call is caught, which is exactly what is wanted: the
 * SSL layer reaches the socket below it through a method pointer, not through
 * the exported PR_Recv symbol, so the ciphertext never shows up here.
 */
static const char *const nss_hints[] = {
	"libnspr4",
	NULL,
};

static const char *const nss_globs[] = {
	"/lib/*/libnspr4.so",
	"/usr/lib/*/libnspr4.so",
	"/usr/lib64/libnspr4.so",
	"/usr/lib/libnspr4.so",
	NULL,
};

static const struct ssl_hook nss_hooks[] = {
	{ "PR_Write", 0, 0 },
	{ "PR_Read",  1, 0 },
	{ "PR_Send",  0, 0 },   /* extra arguments, the first three are the same */
	{ "PR_Recv",  1, 0 },
};

/* GnuTLS: curl, wget and a good part of the GNOME stack */
static const char *const gnutls_hints[] = {
	"libgnutls.so",
	NULL,
};

static const char *const gnutls_globs[] = {
	"/lib/*/libgnutls.so*",
	"/usr/lib/*/libgnutls.so*",
	"/usr/lib64/libgnutls.so*",
	"/usr/lib/libgnutls.so*",
	NULL,
};

static const struct ssl_hook gnutls_hooks[] = {
	{ "gnutls_record_send", 0, 0 },
	{ "gnutls_record_recv", 1, 0 },
};

/* wolfSSL and mbedTLS: embedded and IoT firmware, and the odd desktop client */
static const char *const wolfssl_hints[] = {
	"libwolfssl",
	NULL,
};

static const char *const wolfssl_globs[] = {
	"/usr/lib/*/libwolfssl.so*",
	"/usr/lib/libwolfssl.so*",
	"/usr/local/lib/libwolfssl.so*",
	NULL,
};

static const struct ssl_hook wolfssl_hooks[] = {
	{ "wolfSSL_write", 0, 0 },
	{ "wolfSSL_read",  1, 0 },
};

static const char *const mbedtls_hints[] = {
	"libmbedtls",
	NULL,
};

static const char *const mbedtls_globs[] = {
	"/usr/lib/*/libmbedtls.so*",
	"/usr/lib/libmbedtls.so*",
	"/usr/local/lib/libmbedtls.so*",
	NULL,
};

static const struct ssl_hook mbedtls_hooks[] = {
	{ "mbedtls_ssl_write", 0, 0 },
	{ "mbedtls_ssl_read",  1, 0 },
};

#define TLS_ABI(name, prefix) \
	{ name, prefix##_hints, prefix##_globs, prefix##_hooks, \
	  sizeof(prefix##_hooks) / sizeof(prefix##_hooks[0]) }

static const struct tls_abi tls_abis[] = {
	TLS_ABI("OpenSSL/BoringSSL", openssl),
	TLS_ABI("NSS (NSPR)",        nss),
	TLS_ABI("GnuTLS",            gnutls),
	TLS_ABI("wolfSSL",           wolfssl),
	TLS_ABI("mbedTLS",           mbedtls),
};

#define TLS_ABI_COUNT (sizeof(tls_abis) / sizeof(tls_abis[0]))

/* A library to probe, and the ABI it was recognized as. A NULL abi means the
 * user named the library explicitly: every known symbol set is then tried on
 * it, since a statically linked or renamed library cannot be recognized. */
struct ssl_candidate {
	char path[PATH_MAX];
	const struct tls_abi *abi;
};

#include "go_tls.c"

/*
 * claim_hooked_object
 *
 * Description:
 * Records that a library or executable is being considered for TLS probes.
 * Uprobes are bound to the file rather than to a process, so a file shared by
 * several processes of the tree is hooked once and covers all of them.
 *
 * Params:
 * const char *path: resolved path of the object.
 *
 * Return:
 * 1 if the object is new and has to be hooked, 0 if it was already seen or the
 * table is full.
 * */
static int claim_hooked_object(const char *path)
{
	int i = 0;

	for (i = 0; i < http_hooked_count; i++) {
		if (strcmp(http_hooked_objects[i], path) == 0)
			return 0;
	}

	if (http_hooked_count >= MAX_HOOKED_OBJECTS)
		return 0;

	http_hooked_objects[http_hooked_count] = strdup(path);
	if (!http_hooked_objects[http_hooked_count])
		return 0;
	http_hooked_count++;
	return 1;
}

/*
 * add_unique_lib
 *
 * Description:
 * Appends a library to the candidate list, resolving symlinks and skipping
 * duplicates and unreadable files.
 *
 * Params:
 * struct ssl_candidate *libs: candidate list.
 * int *count: number of entries currently stored, updated on insertion.
 * const char *path: library path to add.
 * const struct tls_abi *abi: ABI it was recognized as, NULL when unknown.
 *
 * Return:
 * 1 if the library has been added, 0 otherwise.
 * */
static int add_unique_lib(struct ssl_candidate *libs, int *count, const char *path,
			  const struct tls_abi *abi)
{
	char resolved[PATH_MAX];
	int i = 0;

	if (*count >= MAX_SSL_LIBS)
		return 0;

	if (!realpath(path, resolved)) {
		/* Android keeps libraries the tracer cannot stat inside the apex
		 * mount namespace: fall back to the path as it was reported. */
		snprintf(resolved, sizeof(resolved), "%s", path);
	}

	if (access(resolved, R_OK) != 0)
		return 0;

	for (i = 0; i < *count; i++) {
		if (strcmp(libs[i].path, resolved) == 0)
			return 0;
	}

	snprintf(libs[*count].path, PATH_MAX, "%s", resolved);
	libs[*count].abi = abi;
	(*count)++;
	return 1;
}

/*
 * collect_mapped_ssl_libs
 *
 * Description:
 * Scans /proc/<pid>/maps looking for the TLS libraries already loaded by the
 * traced process, and tags each of them with the ABI whose hint matched. This
 * is what makes the probe work with no hardcoded path: the Conscrypt apex
 * library shows up in an Android app memory map, and libnspr4.so shows up in
 * Thunderbird's — wherever the distribution or the snap happened to put it.
 *
 * Params:
 * pid_t pid: process to inspect, 0 when unknown.
 * struct ssl_candidate *libs: candidate list to fill.
 * int *count: number of entries currently stored.
 *
 * Return:
 * Number of libraries added.
 * */
static int collect_mapped_ssl_libs(pid_t pid, struct ssl_candidate *libs, int *count)
{
	char maps_path[PATH_MAX];
	char line[PATH_MAX + 128];
	FILE *maps = NULL;
	int added = 0, i = 0;
	size_t a = 0;

	if (pid <= 0)
		return 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	maps = fopen(maps_path, "r");
	if (!maps) {
		log_debug("[?] Cannot read %s: %s", maps_path, strerror(errno));
		return 0;
	}

	while (fgets(line, sizeof(line), maps)) {
		char *path = strchr(line, '/');
		char *newline = NULL;

		/* Anonymous mappings and special regions carry no path */
		if (!path)
			continue;
		newline = strchr(path, '\n');
		if (newline)
			*newline = '\0';

		for (a = 0; a < TLS_ABI_COUNT; a++) {
			const struct tls_abi *abi = &tls_abis[a];

			for (i = 0; abi->hints[i]; i++) {
				if (!strstr(path, abi->hints[i]))
					continue;
				/* No logging here: with -F this scan is repeated
				 * every second over the followed processes, and the
				 * library is reported once, when it is hooked. */
				if (add_unique_lib(libs, count, path, abi))
					added++;
				break;
			}
		}
	}

	fclose(maps);
	return added;
}

/*
 * collect_wellknown_ssl_libs
 *
 * Description:
 * Expands the well known library locations of every known ABI. Used as a
 * fallback, and as a complement, to the memory map scan: a process spawned by
 * ePtracer gets its uprobes installed before it even dlopen()s its TLS library.
 *
 * Params:
 * struct ssl_candidate *libs: candidate list to fill.
 * int *count: number of entries currently stored.
 *
 * Return:
 * Number of libraries added.
 * */
static int collect_wellknown_ssl_libs(struct ssl_candidate *libs, int *count)
{
	glob_t globbuf;
	int added = 0, i = 0;
	size_t a = 0, j = 0;

	for (a = 0; a < TLS_ABI_COUNT; a++) {
		const struct tls_abi *abi = &tls_abis[a];

		for (i = 0; abi->globs[i]; i++) {
			memset(&globbuf, 0, sizeof(globbuf));
			if (glob(abi->globs[i], GLOB_NOSORT, NULL, &globbuf) != 0) {
				globfree(&globbuf);
				continue;
			}
			for (j = 0; j < globbuf.gl_pathc; j++) {
				if (add_unique_lib(libs, count, globbuf.gl_pathv[j], abi)) {
					log_debug("[+] %s found on filesystem: %s",
						  abi->name, globbuf.gl_pathv[j]);
					added++;
				}
			}
			globfree(&globbuf);
		}
	}

	return added;
}

/*
 * collect_user_ssl_libs
 *
 * Description:
 * Parses the comma separated library list given on the command line. Those
 * libraries carry no ABI: every known symbol set is tried on them, which is
 * what makes --ssl-lib useful on a renamed or vendored library.
 *
 * Params:
 * const char *spec: user supplied list, may be NULL or empty.
 * struct ssl_candidate *libs: candidate list to fill.
 * int *count: number of entries currently stored.
 *
 * Return:
 * Number of libraries added.
 * */
static int collect_user_ssl_libs(const char *spec, struct ssl_candidate *libs, int *count)
{
	char *copy = NULL, *token = NULL, *saveptr = NULL;
	int added = 0;

	if (!spec || strlen(spec) == 0)
		return 0;

	copy = strdup(spec);
	if (!copy)
		return 0;

	for (token = strtok_r(copy, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
		while (*token == ' ')
			token++;
		if (*token == '\0')
			continue;
		if (add_unique_lib(libs, count, token, NULL))
			added++;
		else
			log_error("[!] Cannot use TLS library %s: %s", token, strerror(errno));
	}

	free(copy);
	return added;
}

/*
 * attach_abi_hooks
 *
 * Description:
 * Installs the uprobe/uretprobe pairs of one ABI on one library. A symbol that
 * is not exported is not an error: OpenSSL and BoringSSL do not ship the same
 * set, and a library is tried against every ABI when it was named by hand.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * const char *path: library to hook.
 * const struct tls_abi *abi: symbol set to install.
 *
 * Return:
 * Number of symbols hooked.
 * */
static int attach_abi_hooks(struct eptracer_bpf *skel, const char *path,
			    const struct tls_abi *abi)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_program *enter_prog = NULL, *exit_prog = NULL;
	struct bpf_link *link = NULL;
	int attached = 0;
	size_t h = 0;

	for (h = 0; h < abi->hook_count; h++) {
		const struct ssl_hook *hook = &abi->hooks[h];

		enter_prog = hook->is_read ? skel->progs.probe_ssl_read_enter
					   : skel->progs.probe_ssl_write_enter;
		if (hook->is_read)
			exit_prog = hook->is_ex ? skel->progs.probe_ssl_read_ex_exit
						: skel->progs.probe_ssl_read_exit;
		else
			exit_prog = hook->is_ex ? skel->progs.probe_ssl_write_ex_exit
						: skel->progs.probe_ssl_write_exit;

		if (http_link_count + 2 > MAX_HTTP_LINKS)
			break;

		uprobe_opts.func_name = hook->symbol;
		uprobe_opts.retprobe = false;
		link = bpf_program__attach_uprobe_opts(enter_prog, -1, path, 0, &uprobe_opts);
		if (!link) {
			/* Symbol not exported by this library: nothing to do */
			log_debug("[?] %s not hooked in %s: %s", hook->symbol, path,
				  strerror(errno));
			continue;
		}
		http_links[http_link_count++] = link;

		uprobe_opts.retprobe = true;
		link = bpf_program__attach_uprobe_opts(exit_prog, -1, path, 0, &uprobe_opts);
		if (!link) {
			log_error("[!] Failed to hook %s return in %s: %s", hook->symbol,
				  path, strerror(errno));
			continue;
		}
		http_links[http_link_count++] = link;

		log_debug("[+] Hooked %s in %s", hook->symbol, path);
		attached++;
	}

	return attached;
}

/*
 * attach_ssl_candidate
 *
 * Description:
 * Installs the plaintext probes on one library: the symbol set of its ABI
 * when it was recognized, every known one when it was named by hand.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * const struct ssl_candidate *lib: library to hook.
 *
 * Return:
 * Number of symbols hooked.
 * */
static int attach_ssl_candidate(struct eptracer_bpf *skel, const struct ssl_candidate *lib)
{
	int attached = 0;
	size_t a = 0;

	if (lib->abi) {
		attached = attach_abi_hooks(skel, lib->path, lib->abi);
		if (attached > 0) {
			log_info("[+] %s plaintext hooked in %s", lib->abi->name, lib->path);
			/* NSPR carries every kind of I/O the process does, not
			 * only TLS: without the filter the output drowns in
			 * file and pipe reads */
			if (lib->abi->hooks == nss_hooks)
				log_info("[?] NSPR also carries non-TLS I/O: "
					 "-o/--http-only keeps the output readable");
		}
	} else {
		/* Named by hand: no way to tell what it is, so try them all */
		for (a = 0; a < TLS_ABI_COUNT; a++) {
			int got = attach_abi_hooks(skel, lib->path, &tls_abis[a]);

			if (got > 0)
				log_info("[+] %s plaintext hooked in %s",
					 tls_abis[a].name, lib->path);
			attached += got;
		}
	}

	if (attached == 0)
		log_debug("[?] No TLS symbol hooked in %s (stripped, statically "
			  "linked, or an ABI ePtracer does not know)", lib->path);

	return attached;
}

/*
 * attach_ssl_uprobes
 *
 * Description:
 * Finds the TLS libraries the target uses and installs the plaintext probes on
 * every ABI it recognizes.
 *
 * The probes are installed system wide instead of being bound to the target
 * process: perf_event_open() attaches a per-pid uprobe to a single *thread*,
 * which would miss every network thread of a multithreaded application (the
 * common case on Android, and on anything Gecko). Events are filtered in
 * kernel space anyway, by the same TGID check used by the other tracers.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * pid_t pid: target process, only used to read its memory map.
 * const char *lib_spec: user supplied library list, may be NULL.
 *
 * Return:
 * Number of successfully installed probes.
 * */
static int attach_ssl_uprobes(struct eptracer_bpf *skel, pid_t pid, const char *lib_spec)
{
	struct ssl_candidate libs[MAX_SSL_LIBS];
	int lib_count = 0, attached = 0, i = 0;

	memset(libs, 0, sizeof(libs));

	/* An explicit list wins over any autodetection */
	if (collect_user_ssl_libs(lib_spec, libs, &lib_count) == 0) {
		collect_mapped_ssl_libs(pid, libs, &lib_count);
		collect_wellknown_ssl_libs(libs, &lib_count);
	}

	if (lib_count == 0) {
		log_error("[!] No TLS library found. Use --ssl-lib to point ePtracer to one.");
		return 0;
	}

	for (i = 0; i < lib_count; i++) {
		claim_hooked_object(libs[i].path);
		attached += attach_ssl_candidate(skel, &libs[i]);
	}

	return attached;
}

/*
 * resolve_target_exe
 *
 * Description:
 * Finds the executable of the process being traced, which is where a Go
 * program keeps its TLS: statically linked, there is no library to look for.
 *
 * /proc/<pid>/exe is not usable when the process was spawned by ePtracer,
 * because at this point it is still a fork of ePtracer blocked before its
 * execvp() — its exe link points at the tracer. The program name given on the
 * command line is used instead, resolved the way execvp() would.
 *
 * Params:
 * pid_t pid: process being traced.
 * const char *program: -p argument, NULL or empty when attaching with -P.
 * char *out: buffer receiving the path.
 * size_t out_size: its size.
 *
 * Return:
 * 0 on success, -1 when the executable could not be located.
 * */
static int resolve_target_exe(pid_t pid, const char *program, char *out, size_t out_size)
{
	char link[PATH_MAX];
	ssize_t len = 0;

	if (program && program[0]) {
		char first[PATH_MAX];
		const char *space = strchr(program, ' ');
		size_t name_len = space ? (size_t)(space - program) : strlen(program);
		const char *path_env = NULL;
		char *copy = NULL, *dir = NULL, *saveptr = NULL;

		if (name_len == 0 || name_len >= sizeof(first))
			return -1;
		memcpy(first, program, name_len);
		first[name_len] = '\0';

		if (strchr(first, '/'))
			return realpath(first, out) ? 0 : -1;

		path_env = getenv("PATH");
		if (!path_env)
			path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
		copy = strdup(path_env);
		if (!copy)
			return -1;

		for (dir = strtok_r(copy, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
			char candidate[PATH_MAX];

			snprintf(candidate, sizeof(candidate), "%s/%s", dir, first);
			if (access(candidate, X_OK) == 0 && realpath(candidate, out)) {
				free(copy);
				return 0;
			}
		}
		free(copy);
		return -1;
	}

	if (pid <= 0)
		return -1;

	snprintf(link, sizeof(link), "/proc/%d/exe", pid);
	len = readlink(link, out, out_size - 1);
	if (len < 0)
		return -1;
	out[len] = '\0';
	return 0;
}

/*
 * rescan_followed_processes
 *
 * Description:
 * Hooks the TLS code of the child processes followed with -F/--follow-forks.
 * The kernel side follows them on its own, but a uprobe is placed on a file,
 * and a child that executes another program — a helper, a Go tool, a script
 * interpreter — brings libraries the target never mapped. Their memory maps
 * are looked at again on every call, because a library is mapped by the
 * dynamic loader after exec, or dlopen()ed much later; files already seen are
 * skipped, so an unchanged tree costs a /proc read and nothing else.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * int autodetect_libs: 0 when --ssl-lib fixed the library list.
 *
 * Return:
 * Number of probes installed by this call.
 * */
static int rescan_followed_processes(struct eptracer_bpf *skel, int autodetect_libs)
{
	int fd = bpf_map__fd(skel->maps.traced_tgids_map);
	__u32 key = 0, next = 0;
	__u32 *prev = NULL;
	int attached = 0;

	while (bpf_map_get_next_key(fd, prev, &next) == 0) {
		struct ssl_candidate libs[MAX_SSL_LIBS];
		char link[64], exe[PATH_MAX];
		int lib_count = 0, i = 0;
		ssize_t len = 0;

		key = next;
		prev = &key;

		if (autodetect_libs) {
			memset(libs, 0, sizeof(libs));
			collect_mapped_ssl_libs((pid_t)key, libs, &lib_count);
			for (i = 0; i < lib_count; i++) {
				if (claim_hooked_object(libs[i].path))
					attached += attach_ssl_candidate(skel, &libs[i]);
			}
		}

		/* Go keeps its TLS in the executable, not in a library */
		snprintf(link, sizeof(link), "/proc/%u/exe", key);
		len = readlink(link, exe, sizeof(exe) - 1);
		if (len <= 0)
			continue;
		exe[len] = '\0';
		if (claim_hooked_object(exe))
			attached += attach_go_tls(skel, exe);
	}

	if (attached > 0)
		log_debug("[+] %d TLS probes installed for child processes", attached);
	return attached;
}

/*
 * attach_socket_probes
 *
 * Description:
 * Attaches the syscall tracepoints backing the socket layer: connect()/close()
 * maintain the file descriptor to peer mapping, read()/write() and friends
 * carry the cleartext payloads.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 *
 * Return:
 * 0 on success, -1 if a mandatory tracepoint could not be attached.
 * */
static int attach_socket_probes(struct eptracer_bpf *skel)
{
	struct bpf_program *progs[] = {
		skel->progs.trace_connect_enter,
		skel->progs.trace_close_enter,
		skel->progs.trace_sock_write_enter,
		skel->progs.trace_sock_sendto_enter,
		skel->progs.trace_sock_read_enter,
		skel->progs.trace_sock_read_exit,
		skel->progs.trace_sock_recvfrom_enter,
		skel->progs.trace_sock_recvfrom_exit,
	};
	/* the same capture over raw_syscalls, for kernels built without
	 * CONFIG_FTRACE_SYSCALLS (Android GKI): no syscalls/ tracepoint exists */
	struct bpf_program *raw[] = {
		skel->progs.trace_raw_sock_enter,
		skel->progs.trace_raw_sock_exit,
	};
	struct bpf_link *link = NULL;
	int first = http_link_count;
	size_t i = 0;

	for (i = 0; i < sizeof(progs) / sizeof(progs[0]); i++) {
		if (http_link_count >= MAX_HTTP_LINKS)
			return -1;
		link = bpf_program__attach(progs[i]);
		if (!link)
			break;
		http_links[http_link_count++] = link;
	}
	if (i == sizeof(progs) / sizeof(progs[0]))
		return 0;

	log_debug("[?] Per-syscall tracepoints unavailable (%s), falling back to raw_syscalls",
		  strerror(errno));
	while (http_link_count > first)
		bpf_link__destroy(http_links[--http_link_count]);

	for (i = 0; i < sizeof(raw) / sizeof(raw[0]); i++) {
		if (http_link_count >= MAX_HTTP_LINKS)
			return -1;
		link = bpf_program__attach(raw[i]);
		if (!link) {
			log_error("[!] Failed to attach socket tracepoint: %s", strerror(errno));
			return -1;
		}
		http_links[http_link_count++] = link;
	}
	return 0;
}

/*
 * format_peer
 *
 * Description:
 * Renders the peer endpoint of an event as "address:port".
 *
 * Params:
 * const struct conn_info_t *conn: peer information collected from connect(2).
 * char *out: destination buffer.
 * size_t out_size: destination buffer size.
 * */
static void format_peer(const struct conn_info_t *conn, char *out, size_t out_size)
{
	char addr[INET6_ADDRSTRLEN] = {0};

	if (conn->family == 4 && inet_ntop(AF_INET, conn->daddr, addr, sizeof(addr)))
		snprintf(out, out_size, "%s:%u", addr, conn->dport);
	else if (conn->family == 6 && inet_ntop(AF_INET6, conn->daddr, addr, sizeof(addr)))
		snprintf(out, out_size, "[%s]:%u", addr, conn->dport);
	else
		snprintf(out, out_size, "unknown peer");
}

/*
 * is_mostly_printable
 *
 * Description:
 * Tells whether a payload can be rendered as text. Used to pick between the
 * textual view and the hexdump.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 *
 * Return:
 * 1 if at least 85% of the bytes are printable, 0 otherwise.
 * */
static int is_mostly_printable(const char *data, __u32 len)
{
	__u32 printable = 0, i = 0;

	if (len == 0)
		return 1;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)data[i];
		if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
			printable++;
	}

	return (printable * 100 / len) >= 85;
}

/*
 * dump_hex
 *
 * Description:
 * Classic offset/hex/ascii dump, used for binary payloads.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 * */
static void dump_hex(const char *data, __u32 len)
{
	__u32 i = 0, j = 0;
	__u32 shown = len > HTTP_HEXDUMP_MAX ? HTTP_HEXDUMP_MAX : len;

	for (i = 0; i < shown; i += 16) {
		printf("  %04x  ", i);
		for (j = 0; j < 16; j++) {
			if (i + j < shown)
				printf("%02x ", (unsigned char)data[i + j]);
			else
				printf("   ");
		}
		printf(" |");
		for (j = 0; j < 16 && i + j < shown; j++) {
			unsigned char c = (unsigned char)data[i + j];
			printf("%c", isprint(c) ? c : '.');
		}
		printf("|\n");
	}

	if (shown < len)
		printf("  ... %u more bytes\n", len - shown);
}

/*
 * dump_text
 *
 * Description:
 * Prints a payload as text, dropping the carriage returns of the CRLF line
 * endings and escaping the remaining control bytes.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 * __u32 limit: maximum number of bytes to print.
 * */
static void dump_text(const char *data, __u32 len, __u32 limit)
{
	__u32 i = 0;
	__u32 shown = len > limit ? limit : len;

	for (i = 0; i < shown; i++) {
		unsigned char c = (unsigned char)data[i];

		if (c == '\r')
			continue;
		if (c == '\n' || c == '\t' || isprint(c))
			printf("%c", c);
		else
			printf("\\x%02x", c);
	}
	if (shown == 0 || data[shown - 1] != '\n')
		printf("\n");

	if (shown < len)
		printf("... %u more bytes (truncated for readability)\n", len - shown);
}

/*
 * h2_frame_name
 *
 * Description:
 * Maps an HTTP/2 frame type to its name.
 *
 * Params:
 * __u8 type: frame type as defined by RFC 7540 section 6.
 *
 * Return:
 * Frame name, or "UNKNOWN".
 * */
static const char *h2_frame_name(__u8 type)
{
	static const char *const names[] = {
		"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
		"PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION",
	};

	if (type < sizeof(names) / sizeof(names[0]))
		return names[type];
	return "UNKNOWN";
}

/*
 * looks_like_http2
 *
 * Description:
 * Heuristic used on payload chunks that carry no recognizable HTTP/1 start
 * line: a well formed frame header whose length fits the chunk is a strong
 * enough hint that we are looking at an HTTP/2 stream.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 *
 * Return:
 * 1 if the payload starts with a plausible HTTP/2 frame, 0 otherwise.
 * */
static int looks_like_http2(const char *data, __u32 len)
{
	__u32 frame_len = 0;
	__u8 type = 0;

	if (len < 9)
		return 0;

	frame_len = ((__u32)(unsigned char)data[0] << 16) |
		    ((__u32)(unsigned char)data[1] << 8)  |
		     (__u32)(unsigned char)data[2];
	type = (__u8)data[3];

	return type <= 0x09 && frame_len + 9 <= len;
}

/*
 * decode_http2
 *
 * Description:
 * Walks the HTTP/2 frames contained in a payload chunk. DATA frames are
 * rendered, header blocks are reported but not expanded: they are HPACK
 * encoded against a connection wide dynamic table that a single chunk is not
 * enough to reconstruct.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 * */
static void decode_http2(const char *data, __u32 len)
{
	static const char h2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	__u32 off = 0;

	if (len >= sizeof(h2_preface) - 1 &&
	    memcmp(data, h2_preface, sizeof(h2_preface) - 1) == 0) {
		printf("  [h2] connection preface\n");
		off = sizeof(h2_preface) - 1;
	}

	while (off + 9 <= len) {
		__u32 frame_len = ((__u32)(unsigned char)data[off] << 16) |
				  ((__u32)(unsigned char)data[off + 1] << 8) |
				   (__u32)(unsigned char)data[off + 2];
		__u8 type = (__u8)data[off + 3];
		__u8 flags = (__u8)data[off + 4];
		__u32 stream = (((__u32)(unsigned char)data[off + 5] << 24) |
				((__u32)(unsigned char)data[off + 6] << 16) |
				((__u32)(unsigned char)data[off + 7] << 8)  |
				 (__u32)(unsigned char)data[off + 8]) & 0x7fffffffU;
		__u32 payload_len = frame_len;

		off += 9;
		if (off + payload_len > len)
			payload_len = len - off;

		printf("  [h2] %-13s stream=%-3u len=%-5u flags=0x%02x\n",
		       h2_frame_name(type), stream, frame_len, flags);

		if (type == 0x00 && payload_len > 0) {
			/* DATA */
			if (is_mostly_printable(data + off, payload_len))
				dump_text(data + off, payload_len, HTTP_BODY_PRINT_MAX);
			else
				dump_hex(data + off, payload_len);
		} else if ((type == 0x01 || type == 0x05 || type == 0x09) && payload_len > 0) {
			/* HEADERS, PUSH_PROMISE, CONTINUATION */
			printf("       HPACK encoded header block, not decoded\n");
			dump_hex(data + off, payload_len);
		}

		off += payload_len;
		if (frame_len + 9 > len)
			break;
	}
}

/*
 * decode_http1
 *
 * Description:
 * Prints an HTTP/1.x message: start line and headers as text, then the body,
 * rendered as text or as a hexdump depending on its content. Compressed
 * bodies are reported as such instead of being dumped as noise.
 *
 * Params:
 * const char *data: payload.
 * __u32 len: payload length.
 * */
static void decode_http1(const char *data, __u32 len)
{
	const char *body = NULL;
	__u32 header_len = len, body_len = 0;
	__u32 i = 0;

	for (i = 0; i + 3 < len; i++) {
		if (data[i] == '\r' && data[i + 1] == '\n' &&
		    data[i + 2] == '\r' && data[i + 3] == '\n') {
			header_len = i + 2;
			body = data + i + 4;
			body_len = len - (i + 4);
			break;
		}
	}

	dump_text(data, header_len, header_len);

	if (!body || body_len == 0)
		return;

	/* gzip and zlib magic: the body is only readable once inflated */
	if (body_len >= 2 && (unsigned char)body[0] == 0x1f && (unsigned char)body[1] == 0x8b) {
		printf("[body: %u bytes, gzip compressed]\n", body_len);
		dump_hex(body, body_len);
		return;
	}

	if (is_mostly_printable(body, body_len))
		dump_text(body, body_len, HTTP_BODY_PRINT_MAX);
	else
		dump_hex(body, body_len);
}

/*
 * print_chunk_event
 *
 * Description:
 * Renders a single captured chunk, as it was handed to (or returned by) the
 * TLS library. This is the live view: it shows the payloads in the order and
 * with the boundaries the process itself used, and it is the only sensible
 * rendering for anything that is not an HTTP/1.x message, such as HTTP/2
 * frames.
 *
 * Params:
 * const struct http_event_t *ev: event pushed by the BPF programs.
 * */
static void print_chunk_event(const struct http_event_t *ev)
{
	char peer[INET6_ADDRSTRLEN + 16] = {0};
	char timestamp[32] = {0};
	struct tm tm_buf;
	time_t seconds;
	__s64 wall_ns = 0;
	const char *layer = NULL, *arrow = NULL;

	wall_ns = (__s64)ev->timestamp_ns + http_clock_offset_ns;
	seconds = (time_t)(wall_ns / 1000000000LL);
	localtime_r(&seconds, &tm_buf);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_buf);

	format_peer(&ev->conn, peer, sizeof(peer));
	layer = ev->source == HTTP_SRC_TLS ? "TLS  " : "PLAIN";
	arrow = ev->direction == HTTP_EGRESS ? "-->" : "<--";

	printf("\n──── %s.%06u %s %s %s  pid=%u tid=%u comm=%s  %u/%u bytes%s\n",
	       timestamp, (unsigned int)((wall_ns % 1000000000LL) / 1000),
	       layer, arrow, peer, ev->pid, ev->tid, ev->comm,
	       ev->data_len, ev->total_len, ev->truncated ? " [truncated]" : "");

	if (ev->data_len == 0)
		return;

	switch (ev->protocol) {
	case HTTP_PROTO_HTTP1_REQ:
	case HTTP_PROTO_HTTP1_RESP:
		decode_http1(ev->data, ev->data_len);
		break;
	case HTTP_PROTO_HTTP2_PREFACE:
		decode_http2(ev->data, ev->data_len);
		break;
	default:
		/* Continuation chunk: either the rest of an HTTP/1 message, an
		 * HTTP/2 frame stream or an unrelated protocol carried by TLS. */
		if (looks_like_http2(ev->data, ev->data_len))
			decode_http2(ev->data, ev->data_len);
		else if (is_mostly_printable(ev->data, ev->data_len))
			dump_text(ev->data, ev->data_len, HTTP_BODY_PRINT_MAX);
		else
			dump_hex(ev->data, ev->data_len);
		break;
	}

	fflush(stdout);
}

/* Message reassembly, built on the rendering primitives defined above */
#include "http_message.c"
#include "http2_message.c"

/*
 * http_dispatch_event
 *
 * Description:
 * Routes a captured chunk to the reassembler that fits the connection. The
 * choice is made once per connection and kept: HTTP/2 never falls back to
 * HTTP/1, and a connection that turned out to carry something else is left to
 * the chunk view.
 *
 * Params:
 * const struct http_event_t *ev: event delivered by the ring buffer.
 * */
static void http_dispatch_event(const struct http_event_t *ev)
{
	struct http_conn_state *conn_state = find_conn_state(ev->stream_id);

	if (conn_state->protocol_class != HTTP_CLASS_HTTP2) {
		if (ev->protocol == HTTP_PROTO_HTTP2_PREFACE ||
		    (conn_state->protocol_class == HTTP_CLASS_UNKNOWN &&
		     looks_like_http2(ev->data, ev->data_len)))
			conn_state->protocol_class = HTTP_CLASS_HTTP2;
		else if (ev->protocol == HTTP_PROTO_HTTP1_REQ ||
			 ev->protocol == HTTP_PROTO_HTTP1_RESP)
			conn_state->protocol_class = HTTP_CLASS_HTTP1;
		else if (conn_state->protocol_class == HTTP_CLASS_UNKNOWN)
			conn_state->protocol_class = HTTP_CLASS_OTHER;
	}

	switch (conn_state->protocol_class) {
	case HTTP_CLASS_HTTP1:
		http_stream_push(ev);
		break;
	case HTTP_CLASS_HTTP2:
		http2_stream_push(ev);
		break;
	default:
		print_chunk_event(ev);
		break;
	}
}

/*
 * http_event_handler
 *
 * Description:
 * Ring buffer callback: hands the captured chunk either to the reassembler,
 * which rebuilds the requests and the responses as they were exchanged, or to
 * the live chunk view.
 *
 * Params:
 * void *ctx: ring buffer context, unused.
 * void *data: http_event_t pushed by the BPF programs.
 * size_t size: event size.
 *
 * Return:
 * 0, the ring buffer callback never asks for an early stop.
 * */
static int http_event_handler(void *ctx, void *data, size_t size)
{
	const struct http_event_t *ev = (const struct http_event_t *)data;

	if (size < sizeof(*ev) - MAX_HTTP_DATA_SIZE)
		return 0;
	/* Every consumer trusts data_len: hold it to the bytes delivered */
	if (ev->data_len > MAX_HTTP_DATA_SIZE ||
	    ev->data_len > size - offsetof(struct http_event_t, data))
		return 0;

	if (http_chunk_view)
		print_chunk_event(ev);
	else
		http_dispatch_event(ev);

	return 0;
}

/*
 * push_http_config
 *
 * Description:
 * Publishes the capture configuration to the BPF side.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * int tls_only: skip cleartext payloads.
 * int http_only: skip payloads that do not look like HTTP.
 *
 * Return:
 * 0 on success, a negative error otherwise.
 * */
static int push_http_config(struct eptracer_bpf *skel, int tls_only, int http_only)
{
	struct http_config_t cfg = {0};
	__u32 key = 0;

	cfg.capture_tls = 1;
	cfg.capture_plaintext = tls_only ? 0 : 1;
	cfg.http_only = http_only ? 1 : 0;

	return bpf_map_update_elem(bpf_map__fd(skel->maps.http_config_map), &key, &cfg, BPF_ANY);
}

/*
 * init_http_clock_offset
 *
 * Description:
 * Computes the delta between the monotonic clock used by bpf_ktime_get_ns()
 * and the wall clock, so that events can be timestamped in local time.
 * */
static void init_http_clock_offset()
{
	struct timespec monotonic, realtime;

	if (clock_gettime(CLOCK_MONOTONIC, &monotonic) < 0 ||
	    clock_gettime(CLOCK_REALTIME, &realtime) < 0) {
		http_clock_offset_ns = 0;
		return;
	}

	http_clock_offset_ns = ((__s64)realtime.tv_sec - (__s64)monotonic.tv_sec) * 1000000000LL +
			       ((__s64)realtime.tv_nsec - (__s64)monotonic.tv_nsec);
}

/*
 * http_tracer
 *
 * Description:
 * Thread entry point of the HTTP tracer: installs the TLS uprobes and the
 * socket tracepoints, then polls the ring buffer and decodes every captured
 * payload.
 *
 * Params:
 * void *http_tracer_arguments: struct http_tracer_args.
 * */
void *http_tracer(void *http_tracer_arguments)
{
	struct http_tracer_args *arguments = (struct http_tracer_args *)http_tracer_arguments;
	struct eptracer_bpf *skel = arguments->skel;
	char target_exe[PATH_MAX] = {0};
	int ret = 0, tls_probes = 0;
	int autodetect_libs = !arguments->ssl_lib || strlen(arguments->ssl_lib) == 0;
	struct timespec last_rescan;

	init_http_clock_offset();
	http_chunk_view = arguments->chunk_view;
	http_decode_bodies = arguments->decode_bodies;

	if (arguments->dump_dir && strlen(arguments->dump_dir) != 0) {
		if (mkdir(arguments->dump_dir, 0700) < 0 && errno != EEXIST) {
			log_error("[!] Cannot create %s: %s", arguments->dump_dir, strerror(errno));
			return NULL;
		}
		snprintf(http_dump_dir, sizeof(http_dump_dir), "%s", arguments->dump_dir);
		log_debug("[+] Writing captured messages to %s", http_dump_dir);
	}

	if (push_http_config(skel, arguments->tls_only, arguments->http_only) < 0) {
		log_error("[!] Failed to publish HTTP capture configuration");
		return NULL;
	}

	log_debug("[+] Installing TLS uprobes...");
	tls_probes = attach_ssl_uprobes(skel, arguments->pid, arguments->ssl_lib);

	/* A Go program has no TLS library to find: its crypto/tls is inside the
	 * executable itself, hooked through its own symbols and its own ABI */
	if (resolve_target_exe(arguments->pid, arguments->program, target_exe,
			       sizeof(target_exe)) == 0 && claim_hooked_object(target_exe))
		tls_probes += attach_go_tls(skel, target_exe);
	else
		log_debug("[?] Could not locate the traced executable, Go crypto/tls "
			  "will not be hooked");

	if (tls_probes == 0)
		log_error("[!] No TLS probe installed, only cleartext HTTP will be captured");
	else
		log_debug("[+] %d TLS probes installed", tls_probes);

	log_debug("[+] Attaching socket tracepoints...");
	if (attach_socket_probes(skel) < 0) {
		log_error("[!] Failed to attach socket tracepoints");
		return NULL;
	}

	log_debug("[+] Creating a BPF ring buffer manager for HTTP events...");
	http_ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.http_rb_map),
					 http_event_handler, NULL, NULL);
	if (!http_ring_buf) {
		log_error("[!] Error creating HTTP ring buffer manager");
		return NULL;
	}

	/* Children the target already had when ePtracer attached */
	if (arguments->follow_forks)
		rescan_followed_processes(skel, autodetect_libs);
	clock_gettime(CLOCK_MONOTONIC, &last_rescan);

	http_tracer_ready = 1;
	log_debug("[+] Polling HTTP events from ring buffer...");
	while (!stop_requested && (ret = ring_buffer__poll(http_ring_buf, 100)) >= 0) {
		if (arguments->follow_forks) {
			struct timespec now;

			clock_gettime(CLOCK_MONOTONIC, &now);
			if ((now.tv_sec - last_rescan.tv_sec) * 1000 +
			    (now.tv_nsec - last_rescan.tv_nsec) / 1000000 >= HTTP_RESCAN_MS) {
				rescan_followed_processes(skel, autodetect_libs);
				last_rescan = now;
			}
		}

		/* Flush the messages whose connection fell silent: bodies
		 * delimited by the end of the connection end up here */
		if (!http_chunk_view) {
			http_stream_sweep();
			http2_stream_sweep();
		}
	}

	return NULL;
}
