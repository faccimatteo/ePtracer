#!/usr/bin/env python3
"""
End-to-end test of the proxy sandwich: app -> splice -> Burp-style proxy ->
ePtracer UPSTREAM -> the app's own TLS session -> real server.

The oracle is the real server: it records the start line of every request it
receives. The property under test is the one the bridge promises — no request
of the app ever reaches the server more than once — through every path that
could break it: Repeater / retries, Drop, a target edited by hand, a forward that
comes after the app gave up, keys arriving late, strict mode.

The client verifies the server's real certificate with a hostname check (a
pinning app's view), and writes its keylog (the stand-in for eBPF).

Usage: e2e_sandwich.py --relay R --ca CA --cert C --key K --proxy-cert PC --proxy-key PK
"""
import argparse
import collections
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_splice as core  # noqa: E402  (server, client helpers, RECEIVED)

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = 0


def check(cond, msg):
    global FAIL
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAIL += 1


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if not line.startswith("PORT "):
        p.kill()
        raise RuntimeError(f"{cmd[0]} did not start: {p.stderr.read()}")
    return p, int(line.split()[1])


def stop(p):
    p.terminate()
    try:
        _, err = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        _, err = p.communicate()
    return err


def get(path, extra=b""):
    return core.make_req(path.encode(), extra=extra)


def post(path, body):
    return (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: " + core.AUTHORITY.encode() +
            b"\r\nUser-Agent: test-client\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\n\r\n" + body)


def scenario(name, args, srv_port, client, expect_server, relay_extra=(), mock_extra=(),
             asserts=None, settle=0.3):
    """Run one scenario. `client(port, ctx)` returns whatever `asserts` needs.
    `expect_server` is the list of request lines the server must have seen."""
    print(f"[{name}]")
    with tempfile.NamedTemporaryFile(prefix="keylog.", delete=False) as kl:
        keylog = kl.name
    mock_port, bridge_port = free_port(), free_port()
    mock, _ = start([sys.executable, os.path.join(HERE, "burp_style_proxy.py"),
                     "--port", str(mock_port), "--cert", args.proxy_cert, "--key", args.proxy_key,
                     "--upstream", f"127.0.0.1:{bridge_port}", *mock_extra])
    relay, rport = start([args.relay, "--upstream", str(srv_port), "--keylog", keylog,
                          "--proxy-port", str(mock_port), "--bridge-port", str(bridge_port),
                          *relay_extra])
    core.RECEIVED.clear()
    result, err = None, None
    try:
        result = client(rport, core.client_ctx(args.ca, keylog))
    except (ssl.SSLError, OSError) as e:
        err = e
    time.sleep(settle)
    relay_log, mock_log = stop(relay), stop(mock)
    os.unlink(keylog)

    got = list(core.RECEIVED)
    counts = collections.Counter(got)
    check(all(c <= 1 for c in counts.values()),
          f"no request reached the server more than once ({dict(counts) or 'none'})")
    check(sorted(got) == sorted(l.encode() for l in expect_server),
          f"server received exactly {expect_server}")
    if asserts:
        asserts(result, err, relay_log, mock_log)
    stats = [l for l in relay_log.splitlines() if l.startswith("[stats]")]
    if stats:
        print("       " + stats[-1])


def one_shot(reqs, timeout=10):
    def client(port, ctx):
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tls = ctx.wrap_socket(raw, server_hostname=core.AUTHORITY)
        out = []
        for r in reqs:
            tls.sendall(r)
            out.append(core.read_http(tls))
        tls.close()
        return out
    return client


def main():
    ap = argparse.ArgumentParser()
    for a in ("--relay", "--ca", "--cert", "--key", "--proxy-cert", "--proxy-key"):
        ap.add_argument(a, required=True)
    args = ap.parse_args()

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(args.cert, args.key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv_port = srv.getsockname()[1]
    stop_ev = threading.Event()
    threading.Thread(target=core.server_thread, args=(srv, sctx, stop_ev), daemon=True).start()

    # 1. through the proxy, untouched
    def a_pass(res, err, rl, ml):
        check(err is None and res and b"200 OK" in res[0], "response received")
        check(res and b"X-Burp-Mock: forwarded" in res[0], "it went through the proxy")
        check(res and res[0] and res[0].endswith(get("/pass")),
              "the server received the request byte for byte as the app sent it")
    scenario("pass", args, srv_port, one_shot([get("/pass")]),
             ["GET /pass HTTP/1.1"], asserts=a_pass)

    # 2. request edited in the proxy
    def a_edit(res, err, rl, ml):
        check(res and b"User-Agent: EDITED-IN-PROXY" in res[0], "server got the edited request")
    scenario("edit-request", args, srv_port, one_shot([get("/edit")]),
             ["GET /edit HTTP/1.1"], mock_extra=["--replace", "test-client",
                                                 "--replace-to", "EDITED-IN-PROXY"],
             asserts=a_edit)

    # 3. response edited in the proxy
    def a_resp(res, err, rl, ml):
        check(res and b"X-Token: EDITED_BY_PROXY" in res[0] and b"SERVER_TOKEN" not in res[0],
              "app got the edited response")
    scenario("edit-response", args, srv_port, one_shot([get("/resp")]),
             ["GET /resp HTTP/1.1"], mock_extra=["--replace-resp", "SERVER_TOKEN=EDITED_BY_PROXY"],
             asserts=a_resp)

    # 4. keep-alive, several requests, one with a 100 KB body
    body = os.urandom(50000).hex().encode()
    def a_keep(res, err, rl, ml):
        check(err is None and res and len(res) == 3 and all(r and b"200 OK" in r for r in res),
              "three answers on one connection")
        check(res and len(res) == 3 and res[1] and body in res[1],
              "100 KB body delivered intact")
    scenario("keep-alive", args, srv_port,
             one_shot([get("/k1"), post("/k2", body), get("/k3")]),
             ["GET /k1 HTTP/1.1", "POST /k2 HTTP/1.1", "GET /k3 HTTP/1.1"], asserts=a_keep)

    # 5. Repeater / retry: the proxy sends the same request twice
    def a_rep(res, err, rl, ml):
        check(res and b"200 OK" in res[0], "first copy answered")
        check("REPEAT 409" in ml, "second copy refused by ePtracer (409), never delivered")
        check("already delivered (duplicate)" in rl, "bridge logged the duplicate")
    scenario("replay", args, srv_port, one_shot([get("/replay")]),
             ["GET /replay HTTP/1.1"], mock_extra=["--repeat-path", "/replay"], asserts=a_rep)

    # 6. Drop in the proxy
    def a_drop(res, err, rl, ml):
        check(res and b"403 Dropped" in res[0], "app got the proxy's answer")
        check("dropped: the proxy answered the app itself" in rl, "marked DROPPED")
    scenario("drop", args, srv_port, one_shot([get("/drop"), get("/after-drop")]),
             ["GET /after-drop HTTP/1.1"], mock_extra=["--drop-path", "/drop"], asserts=a_drop)

    # 7. the target edited to another port: no request of the app, never delivered
    def a_retarget(res, err, rl, ml):
        check(res and b"400 Bad Request" in res[0], "proxy shows ePtracer's refusal (400)")
        check("RETARGETED /retarget: 400" in ml, "refused at UPSTREAM")
    scenario("target-edited", args, srv_port, one_shot([get("/retarget")]),
             [], mock_extra=["--retarget-path", "/retarget"], asserts=a_retarget)

    # 8. the app gives up while the request sits in Intercept
    def abandon(port, ctx):
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=core.AUTHORITY)
        tls.sendall(get("/slow"))
        time.sleep(0.5)
        tls.close()            # timeout on the app side
        return None
    def a_aband(res, err, rl, ml):
        check("DELAYED 410" in ml, "late forward refused by ePtracer (410)")
        check("abandoned by the app" in rl, "marked ABANDONED when the app closed")
    scenario("abandoned", args, srv_port, abandon, [],
             mock_extra=["--delay-path", "/slow:1.5"], asserts=a_aband, settle=2.0)

    # 9. key late, within the hold: still intercepted
    def a_hold(res, err, rl, ml):
        check(err is None and res and b"X-Burp-Mock: forwarded" in res[0],
              "held until the key came, then through the proxy")
    scenario("key-late-held", args, srv_port, one_shot([get("/held")]),
             ["GET /held HTTP/1.1"], relay_extra=["--key-delay-ms", "150", "--hold-ms", "1000"],
             asserts=a_hold)

    # 10. key too late, strict: closed, nothing reaches the server
    def a_strict(res, err, rl, ml):
        check(err is not None or not res or not res[0], "connection closed by ePtracer")
    scenario("key-late-strict", args, srv_port, one_shot([get("/strict")], timeout=5),
             [], relay_extra=["--key-delay-ms", "3000", "--hold-ms", "100", "--strict"],
             asserts=a_strict)

    # 11. key too late, not strict: relayed once, unseen by the proxy
    def a_loose(res, err, rl, ml):
        check(err is None and res and b"200 OK" in res[0], "app still works")
        check(res and b"X-Burp-Mock" not in res[0], "went straight to the server (not inspectable)")
    scenario("key-late-loose", args, srv_port, one_shot([get("/loose")]),
             ["GET /loose HTTP/1.1"], relay_extra=["--key-delay-ms", "3000", "--hold-ms", "100"],
             asserts=a_loose)

    # 12. the proxy closes its client connection after every answer (Burp may):
    # requests still queued were never shown to it and must go on a new one
    def a_close(res, err, rl, ml):
        check(err is None and res and len(res) == 3 and all(r and b"200 OK" in r for r in res),
              "all three keep-alive requests answered across proxy reconnects")
        check(not any("[bridge]" in l and "dropped" in l for l in rl.splitlines()),
              "nothing marked dropped")
        if FAIL:
            print("\n".join("       | " + l for l in (rl + ml).splitlines()
                            if "[bridge]" in l or "[burp-mock]" in l or "[flow]" in l))
    scenario("proxy-closes-after-each-answer", args, srv_port,
             one_shot([get("/r1"), post("/r2", b"x" * 1000), get("/r3")]),
             ["GET /r1 HTTP/1.1", "POST /r2 HTTP/1.1", "GET /r3 HTTP/1.1"],
             mock_extra=["--close-after-response"], asserts=a_close)

    # 13. the same, but the proxy hangs up without saying so: a request already
    # written on the dying connection is sent again (it never reached the server)
    scenario("proxy-closes-silently", args, srv_port,
             one_shot([get("/s1"), get("/s2"), get("/s3"), get("/s4")]),
             ["GET /s1 HTTP/1.1", "GET /s2 HTTP/1.1", "GET /s3 HTTP/1.1", "GET /s4 HTTP/1.1"],
             mock_extra=["--close-silently"],
             asserts=lambda res, err, rl, ml: check(
                 err is None and res and len(res) == 4 and all(r and b"200 OK" in r for r in res),
                 "all four answered, each delivered once"))

    # 14. the proxy forwards, then hangs up without passing the answer on: the
    # app still gets the server's answer, and nothing is sent twice
    def a_ftc(res, err, rl, ml):
        check(err is None and res and res[0] and b"200 OK" in res[0] and b"/ftc" in res[0],
              "app got the server's own answer")
        check("answered with the server's response" in rl, "answered from UPSTREAM")
        check("duplicate" not in rl, "no second copy was ever sent")
    scenario("proxy-forwards-then-hangs-up", args, srv_port, one_shot([get("/ftc"), get("/after")]),
             ["GET /ftc HTTP/1.1", "GET /after HTTP/1.1"],
             mock_extra=["--forward-then-close-path", "/ftc"], asserts=a_ftc)

    # 15. the proxy hangs up before forwarding: sent again after the grace period
    def a_hang(res, err, rl, ml):
        check(err is None and res and res[0] and b"200 OK" in res[0], "answered after the resend")
        check("sent to the proxy again" in rl, "resent once the grace period was over")
    scenario("proxy-hangs-up-before-forwarding", args, srv_port, one_shot([get("/hang")]),
             ["GET /hang HTTP/1.1"], mock_extra=["--hangup-once-path", "/hang"], asserts=a_hang)

    # 16. Encrypted Client Hello: the SNI on the wire is the provider's public
    # name, the proxy must be told the real host (the Host header)
    def ech_client(port, ctx):
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname="cloudflare-ech.com")
        tls.sendall(get("/ech"))
        r = core.read_http(tls)
        tls.close()
        return [r]
    def a_ech(res, err, rl, ml):
        check(res and res[0] and b"200 OK" in res[0], "answered")
        check("CONNECT api.example.com:" in ml and "CONNECT cloudflare-ech.com" not in ml,
              "the proxy was given the real host, not the outer SNI")
    scenario("ech-real-host", args, srv_port, ech_client, ["GET /ech HTTP/1.1"], asserts=a_ech)

    # 17. keys as the HMAC probe delivers them: no label, no client random
    def a_cand(res, err, rl, ml):
        check(err is None and res and res[0] and b"X-Burp-Mock: forwarded" in res[0],
              "decrypted with unlabeled candidates, through the proxy")
        if FAIL:
            print("\n".join("       | " + l for l in rl.splitlines() if "[bridge]" in l))
    scenario("keys-as-hmac-candidates", args, srv_port, one_shot([get("/cand"), get("/cand2")]),
             ["GET /cand HTTP/1.1", "GET /cand2 HTTP/1.1"],
             relay_extra=["--keys-as-candidates"], asserts=a_cand)

    # 18. WebSocket whose server speaks first (Discord's gateway): the frames
    # right behind the 101 must reach the app, the app's frames the server
    def ws_client(port, ctx):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        tls = ctx.wrap_socket(raw, server_hostname=core.AUTHORITY)
        tls.sendall(b"GET /gateway HTTP/1.1\r\nHost: " + core.AUTHORITY.encode() +
                    b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    b"Sec-WebSocket-Version: 13\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += tls.recv(65536)
        head, _, rest = buf.partition(b"\r\n\r\n")
        out = {"status": head.split(b"\r\n", 1)[0], "hello": None, "echo": None}
        try:
            while len(rest) < 7:
                rest += tls.recv(65536)
            out["hello"] = rest[2:7]
            payload, mask = b"IDENTIFY", b"\x01\x02\x03\x04"
            tls.sendall(bytes([0x81, 0x80 | len(payload)]) + mask +
                        bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))
            rest = rest[7:]
            while len(rest) < 2 + len(payload):
                rest += tls.recv(65536)
            out["echo"] = rest[2:2 + len(payload)]
        except (socket.timeout, OSError):
            pass
        tls.close()
        return out
    def a_ws(res, err, rl, ml):
        check(res and b"101" in res["status"], "WebSocket upgrade answered (101)")
        check(res and res["hello"] == b"HOWDY",
              f"server's first frame reached the app through the proxy, edited ({res and res['hello']})")
        check(res and res["echo"] == b"IDENTIFX",
              f"app's frame reached the server through the proxy, edited ({res and res['echo']})")
        check("WS s2c" in ml and "WS c2s" in ml, "the proxy saw the messages in both directions")
    scenario("websocket-through-proxy", args, srv_port, ws_client,
             ["GET /gateway HTTP/1.1", "WS IDENTIFX"],
             mock_extra=["--ws-replace", "HELLO=HOWDY", "--ws-replace", "IDENTIFY=IDENTIFX"],
             asserts=a_ws)

    stop_ev.set()
    print("\n" + ("FAILED" if FAIL else "PASSED") + f" ({FAIL} failure{'s' if FAIL != 1 else ''})")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
