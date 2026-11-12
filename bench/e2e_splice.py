#!/usr/bin/env python3
"""
End-to-end test of the TLS splice with real TLS 1.3 stacks on both ends.

  client (Python ssl, CA + hostname verification, SSLKEYLOGFILE)
     |
  splice_relay  (bench/splice_relay.c -> src/tracers/tls_splice.c)
     |
  server (Python ssl, real certificate for api.example.com)

The client verifies the *server's own* certificate with a hostname check, so a
MITM would be refused here exactly as a pinning app refuses it. The relay never
holds a certificate: it decrypts and re-encrypts with the session keys the
client logged (the stand-in for the eBPF key capture).

Scenarios (each asserts on what the real server received and what the client
got back, so a successful edit proves the modified bytes were valid TLS records
on the app's own session):

  passthrough   no edit: plaintext is observed, ciphertext relayed as is
  edit-c2s      request header rewritten in flight (length changes)
  edit-split    request rewritten AND re-sent as two records: the two legs'
                sequence numbers diverge; a second keep-alive request proves the
                translation keeps working afterwards
  edit-s2c      response header rewritten in flight

Usage: e2e_splice.py --relay PATH --ca CA --cert CERT --key KEY [--bench N]
"""
import argparse
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

AUTHORITY = "api.example.com"
# start line of every request the real server received, to check that each one
# arrives exactly once
RECEIVED = []


# ---------------------------------------------------------------- server ----

def read_http(sock):
    """Read one HTTP/1.1 message (headers + Content-Length body)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    cl = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            cl = int(v.strip())
    while len(body) < cl:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body[:cl]


def websocket(tls):
    """A gateway-like WebSocket: it speaks first (HELLO right after the 101,
    in the same write, as Discord's gateway does), then echoes each frame.
    Frames received are recorded as "WS <payload>"."""
    tls.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"
                b"\x81\x05HELLO")
    buf = b""
    while True:
        while len(buf) < 6:
            chunk = tls.recv(65536)
            if not chunk:
                return
            buf += chunk
        n = buf[1] & 0x7f              # small frames only: enough for the test
        while len(buf) < 6 + n:
            chunk = tls.recv(65536)
            if not chunk:
                return
            buf += chunk
        mask, data = buf[2:6], buf[6:6 + n]
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
        buf = buf[6 + n:]
        RECEIVED.append(b"WS " + payload)
        tls.sendall(bytes([0x81, len(payload)]) + payload)


def server_thread(srv, ctx, stop):
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            continue
        raw.settimeout(10)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            continue
        try:
            while True:
                req = read_http(tls)
                if not req:
                    break
                RECEIVED.append(req.split(b"\r\n", 1)[0])
                if b"\r\nupgrade: websocket" in req.lower():
                    websocket(tls)
                    break
                size = 0
                for line in req.split(b"\r\n"):
                    if line.lower().startswith(b"x-want-bytes:"):
                        size = int(line.split(b":", 1)[1])
                # echo the request back as the body, so the client can see
                # exactly what reached the server
                body = req if not size else b"Z" * size
                resp = (b"HTTP/1.1 200 OK\r\n"
                        b"X-Token: SERVER_TOKEN\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                tls.sendall(resp)
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass


# ----------------------------------------------------------------- relay ----

def start_relay(relay, upstream, keylog, extra):
    p = subprocess.Popen([relay, "--once", "--upstream", str(upstream), "--keylog", keylog] + extra,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if not line.startswith("PORT "):
        p.kill()
        raise RuntimeError("relay did not start: " + p.stderr.read())
    return p, int(line.split()[1])


def stop_relay(p):
    # the relay exits by itself once the client closed (--once), after printing
    # its stats: wait for that rather than racing it with a signal
    try:
        _, err = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        _, err = p.communicate()
    return err


# ---------------------------------------------------------------- client ----

def client_ctx(ca, keylog, tls12=False):
    ctx = ssl.create_default_context(cafile=ca)       # verifies chain + hostname
    if tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    import os as _os
    if tls12 and _os.environ.get('EPT_CIPHER'):
        ctx.set_ciphers(_os.environ['EPT_CIPHER'])
    ctx.keylog_filename = keylog
    return ctx


def do_requests(port, ctx, requests):
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname=AUTHORITY)
    out = []
    for r in requests:
        tls.sendall(r)
        out.append(read_http(tls))
    tls.close()
    return out


def make_req(path, ua="test-client", extra=b""):
    return (b"GET " + path + b" HTTP/1.1\r\n"
            b"Host: " + AUTHORITY.encode() + b"\r\n"
            b"User-Agent: " + ua.encode() + b"\r\n" + extra +
            b"Content-Length: 0\r\n\r\n")


# ----------------------------------------------------------------- tests ----

FAIL = 0


def check(cond, msg):
    global FAIL
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAIL += 1


def scenario(name, args, srv_port, relay_args, requests, asserts):
    print(f"[{name}]")
    with tempfile.NamedTemporaryFile(prefix="keylog.", delete=False) as kl:
        keylog = kl.name
    p, rport = start_relay(args.relay, srv_port, keylog, relay_args)
    RECEIVED.clear()
    try:
        resps = do_requests(rport, client_ctx(args.ca, keylog, args.tls12), requests)
        err_handshake = None
    except ssl.SSLError as e:
        resps, err_handshake = [], e
    stats = stop_relay(p)
    os.unlink(keylog)
    check(err_handshake is None,
          f"client accepted the real server certificate through the relay ({err_handshake})"
          if err_handshake else "client accepted the real server certificate through the relay")
    sent = [r.split(b"\r\n", 1)[0] for r in requests]
    check(sorted(RECEIVED) == sorted(sent),
          f"real server received each request exactly once ({len(RECEIVED)} for {len(sent)} sent)")
    asserts(resps, stats)
    last = [l for l in stats.splitlines() if l.startswith("[splice] sni=")]
    if last:
        print("       " + last[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--tls12", action="store_true",
                    help="force TLS 1.2 on both ends instead of 1.3")
    ap.add_argument("--bench", type=int, default=0,
                    help="also time N requests direct vs through the splice")
    args = ap.parse_args()

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if args.tls12:
        sctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if args.tls12 and os.environ.get('EPT_CIPHER'):
        sctx.set_ciphers(os.environ['EPT_CIPHER'])
    sctx.load_cert_chain(args.cert, args.key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv_port = srv.getsockname()[1]
    stop = threading.Event()
    threading.Thread(target=server_thread, args=(srv, sctx, stop), daemon=True).start()

    # passthrough: nothing changes, both directions keyed, fast path only
    def a_pass(resps, stats):
        check(len(resps) == 1 and resps[0] and b"200 OK" in resps[0], "response received")
        check(resps and b"User-Agent: test-client" in resps[0],
              "server got the request unchanged")
        check("state=ACTIVE keyed c2s=1 s2c=1" in stats, "both directions decrypted")
        check("resealed=0 | s2c" in stats and stats.rstrip().endswith("resealed=0"),
              "no record re-encrypted (fast path)")
        check("[splice c2s" in stats and "GET /one" in stats,
              "plaintext of the request observed by the splice")
    scenario("passthrough", args, srv_port, ["--plain-log"],
             [make_req(b"/one")], a_pass)

    # edit c2s: the server must see the rewritten header
    def a_edit(resps, stats):
        check(resps and resps[0] and b"User-Agent: ePtracer-edited-agent" in resps[0],
              "server received the edited request (longer header)")
        check(resps and b"test-client" not in resps[0], "original value is gone")
    scenario("edit-c2s", args, srv_port, ["--edit-c2s", "test-client=ePtracer-edited-agent"],
             [make_req(b"/edit")], a_edit)

    # edit + split: sequence numbers diverge, second request must still work
    def a_split(resps, stats):
        check(len(resps) == 2 and all(r and b"200 OK" in r for r in resps),
              "two keep-alive requests answered after the legs diverged")
        check(all(r and b"ePtracer-edited-agent" in r for r in resps if r),
              "both requests reached the server edited")
        check("state=ACTIVE" in stats, "connection still ACTIVE (no FAILED)")
    scenario("edit-split", args, srv_port,
             ["--edit-c2s", "test-client=ePtracer-edited-agent", "--split-c2s"],
             [make_req(b"/a"), make_req(b"/b")], a_split)

    # edit s2c: the client must see the rewritten response header
    def a_s2c(resps, stats):
        check(resps and resps[0] and b"X-Token: EDITED_BY_PROXY" in resps[0],
              "client received the edited response")
        check(resps and b"SERVER_TOKEN" not in resps[0], "original response value is gone")
    scenario("edit-s2c", args, srv_port, ["--edit-s2c", "SERVER_TOKEN=EDITED_BY_PROXY"],
             [make_req(b"/resp")], a_s2c)

    if args.bench:
        bench(args, srv_port, args.bench)

    stop.set()
    print("\n" + ("FAILED" if FAIL else "PASSED") + f" ({FAIL} failure{'s' if FAIL != 1 else ''})")
    sys.exit(1 if FAIL else 0)


# ----------------------------------------------------------------- bench ----

def timed(port, ctx, n, size):
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tls = ctx.wrap_socket(raw, server_hostname=AUTHORITY)
    req = make_req(b"/bench", extra=b"X-Want-Bytes: " + str(size).encode() + b"\r\n")
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        tls.sendall(req)
        read_http(tls)
        samples.append((time.perf_counter() - t0) * 1000)
    tls.close()
    samples.sort()
    return samples[len(samples) // 2], samples[int(len(samples) * 0.99) - 1]


def bench(args, srv_port, n):
    print(f"\n[bench] {n} keep-alive requests per size, p50 / p99 in ms")
    print(f"  {'size':>9} | {'direct':>17} | {'splice passthrough':>19} | {'splice edit':>17}")
    for size in (1024, 65536, 1048576):
        with tempfile.NamedTemporaryFile(prefix="keylog.", delete=False) as kl:
            keylog = kl.name
        ctx = client_ctx(args.ca, keylog, args.tls12)
        d50, d99 = timed(srv_port, ctx, n, size)
        p, rport = start_relay(args.relay, srv_port, keylog, [])
        p50, p99 = timed(rport, ctx, n, size)
        stop_relay(p)
        p, rport = start_relay(args.relay, srv_port, keylog,
                               ["--edit-s2c", "SERVER_TOKEN=EDITED_BY_PROXY"])
        e50, e99 = timed(rport, ctx, n, size)
        stop_relay(p)
        os.unlink(keylog)
        print(f"  {size:>9} | {d50:7.3f} / {d99:7.3f} | {p50:8.3f} / {p99:8.3f} | "
              f"{e50:7.3f} / {e99:7.3f}")


if __name__ == "__main__":
    main()
