/*
 * HTTP tracing — shared definitions between the eBPF programs and userspace.
 *
 * Traffic is captured at two different layers:
 *
 *  - TLS layer: uprobes/uretprobes on SSL_read()/SSL_write() (OpenSSL and
 *    BoringSSL/Conscrypt share the same ABI). The payload is read *before*
 *    encryption and *after* decryption, inside the target process itself, so
 *    certificate pinning is irrelevant: no MITM proxy nor CA store is involved.
 *
 *  - Socket layer: syscall tracepoints (write/sendto/read/recvfrom) for
 *    cleartext HTTP.
 *
 * Peer addresses are resolved without touching kernel structures: connect() is
 * traced to build a (pid, fd) -> peer map, and every socket syscall refreshes
 * the "last socket touched by this thread" entry, which the SSL uretprobes then
 * pick up (the write(2) always happens inside the SSL_write() call).
 */

/* Payload bytes captured per event. A single HTTP message is usually split in
 * several chunks by the library, so userspace reassembles per (tid, ssl_ctx). */
#define MAX_HTTP_DATA_SIZE  4096
/* Bytes peeked to classify a payload as HTTP before capturing it */
#define HTTP_PREFIX_LEN     16
#define HTTP_COMM_LEN       16
/* Ring buffer size: HTTP payloads are much bigger than syscall events */
#define HTTP_RINGBUF_SIZE   (8 * 1024 * 1024)

/* Where the payload was captured */
enum http_source {
    HTTP_SRC_TLS   = 0,   /* SSL_read/SSL_write uprobe (decrypted) */
    HTTP_SRC_PLAIN = 1,   /* socket syscall (cleartext) */
};

/* Traffic direction, from the traced process point of view */
enum http_direction {
    HTTP_EGRESS  = 0,     /* process -> network (requests) */
    HTTP_INGRESS = 1,     /* network -> process (responses) */
};

/* Best-effort protocol classification done in kernel space on the first bytes */
enum http_protocol {
    HTTP_PROTO_UNKNOWN  = 0,  /* not recognized: TLS payload continuation, h2 frame, binary */
    HTTP_PROTO_HTTP1_REQ  = 1,
    HTTP_PROTO_HTTP1_RESP = 2,
    HTTP_PROTO_HTTP2_PREFACE = 3,
};

/* Peer endpoint of a socket, filled from the sockaddr passed to connect(2) */
struct conn_info_t {
    __u8  daddr[16];      /* IPv4 in the first 4 bytes when family == 4 */
    __u16 dport;
    __u8  family;         /* 0 unknown, 4 AF_INET, 6 AF_INET6 */
    __u8  is_http;        /* a payload carried by this socket was recognized as HTTP */
};

/* Event pushed to userspace through http_rb_map */
struct http_event_t {
    __u64 timestamp_ns;
    /* Identifies the connection the chunk belongs to, so that userspace can
     * reassemble messages: the SSL* pointer for TLS, (pid << 32 | fd) for
     * cleartext sockets. */
    __u64 stream_id;
    __u32 pid;
    __u32 tid;
    __u32 data_len;       /* bytes actually copied in data[] */
    __u32 total_len;      /* bytes the process really read/wrote */
    struct conn_info_t conn;
    __u8  source;         /* enum http_source */
    __u8  direction;      /* enum http_direction */
    __u8  protocol;       /* enum http_protocol */
    __u8  truncated;      /* data_len < total_len */
    char  comm[HTTP_COMM_LEN];
    char  data[MAX_HTTP_DATA_SIZE];
};

/* Arguments stashed at SSL_read/SSL_write entry, consumed by the uretprobe */
struct ssl_args_t {
    __u64 ssl_ctx;
    __u64 buf;
    __u64 num;
    __u64 ex_written;     /* size_t* out parameter of SSL_{read,write}_ex */
};

/* Arguments stashed at read/recvfrom entry, consumed at syscall exit */
struct sock_read_args_t {
    __u64 buf;
    __u32 fd;
};

/* Runtime configuration, pushed by userspace in http_config_map */
struct http_config_t {
    __u8 capture_tls;         /* capture SSL_read/SSL_write payloads */
    __u8 capture_plaintext;   /* capture cleartext socket payloads */
    __u8 http_only;           /* drop payloads not classified as HTTP */
};

/* structure to send arguments to the http_tracer thread */
struct http_tracer_args {
    struct eptracer_bpf *skel;
    pid_t  pid;               /* target PID, 0 when tracing by program name */
    char  *program;           /* -p command line, NULL when attaching to a PID */
    char  *ssl_lib;           /* comma separated library override, may be NULL/empty */
    int    follow_forks;      /* also hook the TLS libraries the child processes load */
    int    tls_only;
    int    http_only;
    int    chunk_view;        /* show raw chunks instead of reassembled messages */
    int    decode_bodies;     /* unchunk and decompress bodies, rewriting their headers */
    char  *dump_dir;          /* directory where each message is written verbatim */
};

void *http_tracer(void *http_tracer_arguments);
