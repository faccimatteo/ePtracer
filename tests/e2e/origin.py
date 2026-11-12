#!/usr/bin/env python3
"""
Test origin for the e2e suite: one cleartext HTTP/1.1 listener and one HTTPS
(TLS 1.2+/HTTP/1.1) listener, standard library only.

Every request is logged as "REQ <method> <path>" to --log, and answered with a
small body echoing the path plus an `x-token: SERVER_TOKEN` header, which the
splice scenario has the proxy rewrite.
"""
import argparse
import http.server
import ssl
import sys
import threading


def handler_for(log):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _answer(self):
            n = int(self.headers.get("content-length") or 0)
            if n:
                self.rfile.read(n)
            with open(log, "a") as f:
                f.write(f"REQ {self.command} {self.path}\n")
            body = f"hello from the origin, {self.path}\n".encode()
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("x-token", "SERVER_TOKEN")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, *a):
            pass

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--http-port", type=int, required=True)
    ap.add_argument("--https-port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    h = handler_for(a.log)
    plain = http.server.ThreadingHTTPServer((a.host, a.http_port), h)
    tls = http.server.ThreadingHTTPServer((a.host, a.https_port), h)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)

    threading.Thread(target=plain.serve_forever, daemon=True).start()
    print("READY", flush=True)
    try:
        tls.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
