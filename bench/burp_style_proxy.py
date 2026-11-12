#!/usr/bin/env python3
"""
Burp-style HTTP proxy mock, for testing the ePtracer proxy bridge.

Towards its client it behaves like Burp/Caido:

  1. accepts `CONNECT <authority>:<port>`, answers 200;
  2. terminates TLS as a man in the middle with a leaf certificate minted by its
     own CA (--cert/--key);
  3. reads each decrypted request (keep-alive), applies the rules below, then
  4. either answers itself (default, "terminate" mode: enough for the FRONT
     compatibility test), or, with --upstream HOST:PORT, forwards the request
     through an upstream proxy exactly as Burp does with "Upstream proxy
     servers": CONNECT to it, TLS without verifying its certificate (Burp's
     default), request, response back to the client.

Rules, to exercise the bridge's at-most-once guarantee (paths match the request
target exactly):

  --replace FROM --replace-to TO     Match & Replace on requests
  --replace-resp FROM=TO             Match & Replace on responses
  --drop-path P                      Drop: answer the client, never forward
  --repeat-path P                    forward the same request twice (Repeater,
                                     or a retry): the second answer's status is
                                     logged as "REPEAT <status>"
  --retarget-path P                  send P upstream to another port than the
                                     one the client asked for (a user editing
                                     the target in Repeater)
  --delay-path P:SECONDS             hold it in "Intercept" before forwarding;
                                     logged as "DELAYED <status>"
  --close-after-response             close the client connection after every
                                     answer ("Connection: close"), as Burp may
  --close-silently                   the same, without announcing it
  --forward-then-close-path P        forward P, then hang up without passing the
                                     answer on (seen with Burp in the field)
  --hangup-once-path P               the first time, hang up on P without
                                     forwarding it
  --ws-replace FROM=TO               after a 101, edit WebSocket messages in
                                     both directions (frames re-encoded, client
                                     frames re-masked); each message is logged
                                     as "WS c2s|s2c <payload>"

Decisions are logged on stderr. Standard library only. A TEST FIXTURE: it MITMs
only what a local test client sends it, with a throwaway CA.
"""
import argparse
import select
import socket
import ssl
import sys
import threading
import time

CRLF = b"\r\n"


def log(msg):
    print(f"[burp-mock] {msg}", file=sys.stderr, flush=True)


def recv_headers(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return buf
        buf += chunk
    return buf


def read_message(sock, buf=b"", is_response=False):
    """Read one HTTP/1.1 message (Content-Length or chunked). Returns
    (message, leftover) or (None, b"") at EOF."""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    head += b"\r\n\r\n"
    cl, chunked = None, False
    for line in head.split(CRLF)[1:]:
        k, _, v = line.partition(b":")
        k = k.strip().lower()
        if k == b"content-length":
            cl = int(v.strip())
        elif k == b"transfer-encoding" and b"chunked" in v.lower():
            chunked = True
    if chunked:
        body = b""
        while True:
            while CRLF not in rest:
                rest += sock.recv(65536)
            size_line, _, rest = rest.partition(CRLF)
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                # last chunk: optional trailer fields, then the blank line
                while not rest.startswith(CRLF) and b"\r\n\r\n" not in rest:
                    rest += sock.recv(65536)
                end = 2 if rest.startswith(CRLF) else rest.index(b"\r\n\r\n") + 4
                return head + body + size_line + CRLF + rest[:end], rest[end:]
            while len(rest) < size + 2:
                rest += sock.recv(65536)
            body += size_line + CRLF + rest[:size + 2]
            rest = rest[size + 2:]
    n = cl or 0
    while len(rest) < n:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return head + rest[:n], rest[n:]


def path_of(req):
    parts = req.split(CRLF, 1)[0].split()
    return parts[1].decode() if len(parts) > 1 else ""


def status_of(resp):
    parts = resp.split(CRLF, 1)[0].split() if resp else []
    return parts[1].decode() if len(parts) > 1 else "none"


class Upstream:
    """One connection to the upstream proxy per client connection, like Burp."""

    def __init__(self, host, port, authority):
        self.host, self.port, self.authority = host, port, authority
        self.tls, self.buf = None, b""

    def open(self):
        raw = socket.create_connection((self.host, self.port), timeout=15)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.sendall(b"CONNECT " + self.authority.encode() + b" HTTP/1.1\r\nHost: "
                    + self.authority.encode() + b"\r\n\r\n")
        reply = recv_headers(raw)
        if not reply.startswith(b"HTTP/1.1 200"):
            raise OSError("upstream refused CONNECT: %r" % reply[:60])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # Burp does not verify upstream
        self.tls = ctx.wrap_socket(raw, server_hostname=self.authority.split(":")[0])

    def exchange(self, req):
        if self.tls is None:
            self.open()
        self.tls.sendall(req)
        resp, self.buf = read_message(self.tls, self.buf, is_response=True)
        return resp

    def close(self):
        if self.tls:
            try:
                self.tls.close()
            except OSError:
                pass


def handle_plain(conn, args):
    conn.settimeout(15)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    head = recv_headers(conn)
    if not head:
        return
    parts = head.split(CRLF, 1)[0].decode("latin1", "replace").split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
        return
    authority = parts[1]
    log(f"CONNECT {authority}")
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as e:
        log(f"TLS termination failed: {e}")
        return

    up = Upstream(*args.upstream, authority) if args.upstream else None
    try:
        buf = b""
        while True:
            req, buf = read_message(tls, buf)
            if not req:
                break
            r = handle_request(tls, req, authority, up, args)
            if r == "ws":
                ws_pump(tls, buf, up, args)
                break
            if not r:
                break
    except (ssl.SSLError, OSError) as e:
        log(f"connection ended: {e}")
    finally:
        if up:
            up.close()
        try:
            tls.close()
        except OSError:
            pass


def handle_request(tls, req, authority, up, args):
    path = path_of(req)
    log(f"  request {req.split(CRLF, 1)[0].decode('latin1')}")

    replaced = False
    if args.replace and args.replace.encode() in req:
        req = req.replace(args.replace.encode(), args.replace_to.encode())
        replaced = True

    if up is None:
        # terminate mode: echo what would have been forwarded
        hdr = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
               b"X-Burp-Mock-Authority: " + authority.encode() + b"\r\n"
               + (b"X-Burp-Mock-Replaced: 1\r\n" if replaced else b"")
               + b"Content-Length: " + str(len(req)).encode() + b"\r\n\r\n")
        tls.sendall(hdr + req)
        return True

    if path in args.drop_path:
        log(f"DROPPED {path}")
        tls.sendall(b"HTTP/1.1 403 Dropped by proxy\r\nContent-Length: 0\r\n\r\n")
        return True

    if path in args.retarget_path:
        host = authority.rsplit(":", 1)[0]
        other = Upstream(*args.upstream, f"{host}:443")
        resp = other.exchange(req)
        other.close()
        log(f"RETARGETED {path}: {status_of(resp)}")
        if resp:
            tls.sendall(resp)
        return True

    if path in args.hangup_once_path and path not in args.hung_up:
        args.hung_up.add(path)
        log(f"HUNG UP on {path} without forwarding")
        return False

    delay = args.delay.get(path)
    if delay:
        log(f"HOLDING {path} for {delay}s")
        time.sleep(delay)

    resp = up.exchange(req)
    if delay:
        log(f"DELAYED {status_of(resp)}")

    if path in args.repeat_path:
        again = up.exchange(req)
        log(f"REPEAT {status_of(again)}")

    if resp is None:
        return False
    if path in args.forward_then_close_path:
        log(f"FORWARDED {path} then hung up ({status_of(resp)} not passed on)")
        return False
    for frm, to in args.replace_resp:
        resp = resp.replace(frm.encode(), to.encode())
    resp = resp.replace(b"\r\n", b"\r\nX-Burp-Mock: forwarded\r\n", 1)
    if args.close_after_response and not args.close_silently and status_of(resp) != "101":
        resp = resp.replace(b"\r\n", b"\r\nConnection: close\r\n", 1)
    try:
        tls.sendall(resp)
    except OSError:
        log("client gone before the answer")
        return False
    if status_of(resp) == "101":
        log("WS upgraded")
        return "ws"
    if args.close_after_response or args.close_silently:
        log("closing the client connection after the answer")
        return False
    return True


def ws_frames(buf, edits, direction):
    """Split complete WebSocket frames off buf, edit data frames, re-encode.
    Returns (bytes to send, leftover)."""
    out = b""
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        masked, n, pos = b1 & 0x80, b1 & 0x7f, 2
        if n == 126:
            if len(buf) < 4:
                break
            n, pos = int.from_bytes(buf[2:4], "big"), 4
        elif n == 127:
            if len(buf) < 10:
                break
            n, pos = int.from_bytes(buf[2:10], "big"), 10
        key = buf[pos:pos + 4] if masked else b""
        pos += 4 if masked else 0
        if len(buf) < pos + n:
            break
        data = buf[pos:pos + n]
        if masked:
            data = bytes(c ^ key[i % 4] for i, c in enumerate(data))
        buf = buf[pos + n:]
        if b0 & 0x0f in (1, 2):          # text / binary: what Burp lets you edit
            for frm, to in edits:
                data = data.replace(frm.encode(), to.encode())
            log(f"WS {direction} {data[:60]!r}")
        n = len(data)
        hdr = bytes([b0])
        mbit = 0x80 if masked else 0
        if n < 126:
            hdr += bytes([mbit | n])
        elif n < 65536:
            hdr += bytes([mbit | 126]) + n.to_bytes(2, "big")
        else:
            hdr += bytes([mbit | 127]) + n.to_bytes(8, "big")
        if masked:
            data = key + bytes(c ^ key[i % 4] for i, c in enumerate(data))
        out += hdr + data
    return out, buf


def ws_pump(client, client_buf, up, args):
    """Relay a WebSocket between the client and the upstream, message by
    message, the way Burp's WebSockets history sees it."""
    ends = {client: up.tls, up.tls: client}
    bufs = {client: client_buf, up.tls: up.buf}
    names = {client: "c2s", up.tls: "s2c"}
    for s in ends:
        s.setblocking(False)

    def flush(src):
        out, bufs[src] = ws_frames(bufs[src], args.ws_replace, names[src])
        if out:
            dst = ends[src]
            dst.setblocking(True)
            dst.sendall(out)
            dst.setblocking(False)

    for src in ends:
        flush(src)          # what came along with the 101
    try:
        while True:
            ready = [s for s in ends if s.pending()]
            if not ready:
                ready, _, _ = select.select(list(ends), [], [], 0.5)
            for src in ready:
                try:
                    data = src.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                if not data:
                    log("WS closed")
                    return
                bufs[src] += data
                flush(src)
    except (OSError, ssl.SSLError) as e:
        log(f"WS ended: {e}")


def serve(args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(64)
    print(f"PORT {srv.getsockname()[1]}", flush=True)
    log(f"listening on {args.host}:{srv.getsockname()[1]}"
        + (f", upstream {args.upstream[0]}:{args.upstream[1]}" if args.upstream else ""))
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle_plain, args=(conn, args), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = ephemeral, printed as 'PORT n'")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--upstream", default="", help="HOST:PORT of the upstream proxy")
    ap.add_argument("--replace", default="")
    ap.add_argument("--replace-to", dest="replace_to", default="")
    ap.add_argument("--replace-resp", action="append", default=[])
    ap.add_argument("--drop-path", action="append", default=[])
    ap.add_argument("--repeat-path", action="append", default=[])
    ap.add_argument("--retarget-path", action="append", default=[])
    ap.add_argument("--delay-path", action="append", default=[])
    ap.add_argument("--ws-replace", action="append", default=[])
    ap.add_argument("--close-after-response", action="store_true")
    ap.add_argument("--close-silently", action="store_true")
    ap.add_argument("--forward-then-close-path", action="append", default=[])
    ap.add_argument("--hangup-once-path", action="append", default=[])
    ap.add_argument("--terminate", action="store_true", default=True)
    args = ap.parse_args()
    if args.upstream:
        h, _, p = args.upstream.rpartition(":")
        args.upstream = (h, int(p))
    else:
        args.upstream = None
    args.replace_resp = [tuple(r.split("=", 1)) for r in args.replace_resp]
    args.ws_replace = [tuple(r.split("=", 1)) for r in args.ws_replace]
    args.hung_up = set()
    args.delay = {}
    for d in args.delay_path:
        p, _, s = d.rpartition(":")
        args.delay[p] = float(s)
    serve(args)


if __name__ == "__main__":
    main()
