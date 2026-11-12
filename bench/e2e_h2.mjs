// End-to-end test of HTTP/2 through the proxy sandwich (bench/run_e2e_sandwich.sh).
//
//   node h2 client (real cert verified, keylog) -> sandwich_relay -> Burp-style
//   proxy (HTTP/1.1) -> ePtracer UPSTREAM -> h2 on the app's own TLS session ->
//   node h2 server
//
// Oracle: the real server records every stream it receives. The property is
// the same as for HTTP/1.1 — no request reaches the server more than once —
// now with multiplexed streams, stream resets and trailers.
//
// Usage: node e2e_h2.mjs --relay R --ca CA --cert C --key K --proxy-cert PC --proxy-key PK
import http2 from 'node:http2';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const AUTHORITY = 'api.example.com';
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) =>
  (v.startsWith('--') ? a.concat([[v.slice(2), all[i + 1]]]) : a), []));

let FAIL = 0;
const check = (cond, msg) => { console.log((cond ? '  ok   ' : '  FAIL ') + msg); if (!cond) FAIL++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

// ---- the real server --------------------------------------------------------
const RECEIVED = [];
const server = http2.createSecureServer({
  key: fs.readFileSync(args.key), cert: fs.readFileSync(args.cert), allowHTTP1: false,
});
server.on('stream', (stream, h) => {
  RECEIVED.push(`${h[':method']} ${h[':path']}`);
  const chunks = [];
  stream.on('data', c => chunks.push(c));
  stream.on('end', () => {
    const body = Buffer.concat(chunks);
    const info = JSON.stringify({ path: h[':path'], ua: h['user-agent'] || '',
                                  cookie: h.cookie || '', len: body.length, sha: sha(body) });
    if (h[':path'] === '/trailers') {
      stream.respond({ ':status': 200, 'content-type': 'application/grpc' },
                     { waitForTrailers: true });
      stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0', 'grpc-message': 'ok' }));
      stream.end(info);
      return;
    }
    stream.respond({ ':status': 200, 'x-token': 'SERVER_TOKEN' });
    stream.end(info);
  });
  stream.on('error', () => {});
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const SERVER_PORT = server.address().port;

// ---- processes --------------------------------------------------------------
function freePort() {
  return new Promise(r => { const s = tls.createServer(); s.listen(0, '127.0.0.1', () => {
    const p = s.address().port; s.close(() => r(p)); }); });
}

function start(cmd, argv) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, argv, { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '', out = '';
    p.stderr.on('data', d => { err += d; });
    p.stdout.on('data', d => {
      out += d;
      const m = out.match(/^PORT (\d+)/m);
      if (m && !p.port) { p.port = +m[1]; resolve(p); }
    });
    p.on('exit', () => { if (!p.port) reject(new Error(`${cmd}: ${err}`)); });
    p.logs = () => err;
  });
}

function stop(p) {
  return new Promise(r => { p.on('exit', () => r(p.logs())); p.kill('SIGTERM');
                            setTimeout(() => p.kill('SIGKILL'), 5000); });
}

// ---- the app ---------------------------------------------------------------
function connect(port, keylog) {
  const client = http2.connect(`https://${AUTHORITY}`, {
    createConnection: () => {
      const s = tls.connect({ host: '127.0.0.1', port, servername: AUTHORITY,
                              ca: fs.readFileSync(args.ca), ALPNProtocols: ['h2'] });
      s.on('keylog', line => fs.appendFileSync(keylog, line));
      return s;
    },
  });
  client.on('error', () => {});
  return client;
}

function request(client, reqPath, { method = 'GET', body = null, headers = {} } = {}) {
  return new Promise(resolve => {
    const req = client.request({ ':method': method, ':path': reqPath, 'user-agent': 'test-client',
                                 ...headers }, { endStream: !body });
    const res = { status: 0, headers: {}, body: Buffer.alloc(0), trailers: null, error: null, req };
    req.on('response', h => { res.status = h[':status']; res.headers = h; });
    req.on('trailers', t => { res.trailers = t; });
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => { res.body = Buffer.concat(chunks); resolve(res); });
    req.on('error', e => { res.error = e; resolve(res); });
    req.on('close', () => resolve(res));
    if (body) req.end(body);
  });
}

// ---- scenarios -------------------------------------------------------------
async function scenario(name, { mockExtra = [], expect, run, asserts }) {
  console.log(`[${name}]`);
  const keylog = path.join(os.tmpdir(), `eptracer-h2-keylog-${process.pid}-${Date.now()}`);
  fs.writeFileSync(keylog, '');
  const mockPort = await freePort(), bridgePort = await freePort();
  const mock = await start('python3', [path.join(HERE, 'burp_style_proxy.py'), '--port', String(mockPort),
    '--cert', args['proxy-cert'], '--key', args['proxy-key'],
    '--upstream', `127.0.0.1:${bridgePort}`, ...mockExtra]);
  const relay = await start(args.relay, ['--upstream', String(SERVER_PORT), '--keylog', keylog,
    '--proxy-port', String(mockPort), '--bridge-port', String(bridgePort)]);

  RECEIVED.length = 0;
  const client = connect(relay.port, keylog);
  let result, err = null;
  try {
    result = await run(client);
  } catch (e) {
    err = e;
  }
  const alpn = client.alpnProtocol;
  client.close();
  await sleep(300);
  const relayLog = await stop(relay), mockLog = await stop(mock);
  fs.rmSync(keylog, { force: true });

  check(alpn === 'h2', `app negotiated h2 with the real server (${alpn})`);
  const counts = {};
  for (const r of RECEIVED) counts[r] = (counts[r] || 0) + 1;
  check(Object.values(counts).every(c => c <= 1),
        `no request reached the server more than once (${JSON.stringify(counts)})`);
  check(JSON.stringify([...RECEIVED].sort()) === JSON.stringify([...expect].sort()),
        `server received exactly ${JSON.stringify(expect)}`);
  if (err) check(false, `client error: ${err.message}`);
  else asserts(result, relayLog, mockLog);
  const stats = relayLog.split('\n').filter(l => l.startsWith('[stats]')).pop();
  if (stats) console.log('       ' + stats);
}

const viaProxy = r => r && r.headers && r.headers['x-burp-mock'] === 'forwarded';

await scenario('h2-single', {
  expect: ['GET /one'],
  run: c => request(c, '/one'),
  asserts: r => {
    check(r.status === 200, `status 200 (${r.status})`);
    check(viaProxy(r), 'went through the proxy');
    check(JSON.parse(r.body).path === '/one', 'body is the server answer');
  },
});

await scenario('h2-concurrent', {
  expect: ['GET /c1', 'GET /c2', 'GET /c3', 'GET /c4', 'GET /c5'],
  run: c => Promise.all(['/c1', '/c2', '/c3', '/c4', '/c5'].map(p => request(c, p))),
  asserts: rs => {
    check(rs.every(r => r.status === 200 && viaProxy(r)), 'five multiplexed streams answered via the proxy');
    check(rs.every((r, i) => JSON.parse(r.body).path === `/c${i + 1}`),
          'each stream got its own answer (routed by stream id)');
  },
});

const big = crypto.randomBytes(200 * 1024);
await scenario('h2-proxy-closes-after-each-answer', {
  mockExtra: ['--close-after-response'],
  expect: ['GET /k1', 'GET /k2', 'GET /k3', 'GET /k4', 'GET /k5'],
  run: c => Promise.all(['/k1', '/k2', '/k3', '/k4', '/k5'].map(p => request(c, p))),
  asserts: (rs, rl) => {
    check(rs.every(r => r.status === 200 && viaProxy(r)), 'five streams answered across proxy reconnects');
    check(!rl.split('\n').some(l => l.includes('[bridge]') && l.includes('dropped')), 'nothing marked dropped');
  },
});

await scenario('h2-post-body-cookies', {
  expect: ['POST /upload'],
  run: c => request(c, '/upload', { method: 'POST', body: big,
                                    headers: { cookie: ['a=1', 'b=2'] } }),
  asserts: r => {
    const info = JSON.parse(r.body);
    check(info.len === big.length && info.sha === sha(big), '200 KB body delivered intact');
    check(info.cookie === 'a=1; b=2', `split cookies joined (${info.cookie})`);
  },
});

await scenario('h2-edit-request-response', {
  mockExtra: ['--replace', 'test-client', '--replace-to', 'EDITED-IN-PROXY',
              '--replace-resp', 'SERVER_TOKEN=EDITED_BY_PROXY'],
  expect: ['GET /edit'],
  run: c => request(c, '/edit'),
  asserts: r => {
    check(JSON.parse(r.body).ua === 'EDITED-IN-PROXY', 'server got the edited request');
    check(r.headers['x-token'] === 'EDITED_BY_PROXY', 'app got the edited response');
  },
});

await scenario('h2-replay', {
  mockExtra: ['--repeat-path', '/replay'],
  expect: ['GET /replay'],
  run: c => request(c, '/replay'),
  asserts: (r, rl, ml) => {
    check(r.status === 200, 'first copy answered');
    check(ml.includes('REPEAT 409'), 'second copy refused (409), never delivered');
  },
});

await scenario('h2-drop', {
  mockExtra: ['--drop-path', '/drop'],
  expect: ['GET /kept'],
  run: c => Promise.all([request(c, '/drop'), request(c, '/kept')]),
  asserts: ([d, k], rl) => {
    check(d.status === 403, `dropped stream answered by the proxy (${d.status})`);
    check(k.status === 200 && viaProxy(k), 'the other stream unaffected');
    check(rl.includes('dropped: the proxy answered the app itself'), 'marked DROPPED');
  },
});

// the app resets one stream while the proxy holds it in Intercept
await (async () => {
  console.log('[h2-reset-while-in-proxy]');
  const keylog = path.join(os.tmpdir(), `eptracer-h2-keylog-${process.pid}-r`);
  fs.writeFileSync(keylog, '');
  const mockPort = await freePort(), bridgePort = await freePort();
  const mock = await start('python3', [path.join(HERE, 'burp_style_proxy.py'), '--port', String(mockPort),
    '--cert', args['proxy-cert'], '--key', args['proxy-key'], '--upstream', `127.0.0.1:${bridgePort}`,
    '--delay-path', '/slow:1.5']);
  const relay = await start(args.relay, ['--upstream', String(SERVER_PORT), '--keylog', keylog,
    '--proxy-port', String(mockPort), '--bridge-port', String(bridgePort)]);
  RECEIVED.length = 0;
  const c = connect(relay.port, keylog);
  const req = c.request({ ':method': 'GET', ':path': '/slow', 'user-agent': 'test-client' });
  req.on('error', () => {});
  await sleep(400);
  req.close(http2.constants.NGHTTP2_CANCEL);   // RST_STREAM: the app gives up
  const after = await request(c, '/after');      // the connection is still usable
  await sleep(2000);                             // let the proxy forward the stale one
  c.close();
  await sleep(300);
  const rl = await stop(relay), ml = await stop(mock);
  fs.rmSync(keylog, { force: true });
  check(!RECEIVED.includes('GET /slow'), `cancelled stream never reached the server (${JSON.stringify(RECEIVED)})`);
  check(RECEIVED.filter(x => x === 'GET /after').length === 1, 'next stream delivered once');
  check(after.status === 200, 'connection still usable after the reset');
  check(rl.includes('abandoned: the app reset its stream'), 'marked ABANDONED on RST_STREAM');
  check(ml.includes('DELAYED 410'), 'late forward refused (410)');
})();

// Eight slow requests take every parallel slot towards the proxy, so a ninth
// waits in ePtracer's queue; the app resets it there: the proxy never sees it.
await (async () => {
  console.log('[h2-reset-while-queued]');
  const keylog = path.join(os.tmpdir(), `eptracer-h2-keylog-${process.pid}-q`);
  fs.writeFileSync(keylog, '');
  const mockPort = await freePort(), bridgePort = await freePort();
  const holds = Array.from({ length: 8 }, (_, i) => `/hold${i + 1}`);
  const mock = await start('python3', [path.join(HERE, 'burp_style_proxy.py'), '--port', String(mockPort),
    '--cert', args['proxy-cert'], '--key', args['proxy-key'], '--upstream', `127.0.0.1:${bridgePort}`,
    ...holds.flatMap(h => ['--delay-path', `${h}:1.0`])]);
  const relay = await start(args.relay, ['--upstream', String(SERVER_PORT), '--keylog', keylog,
    '--proxy-port', String(mockPort), '--bridge-port', String(bridgePort)]);
  RECEIVED.length = 0;
  const c = connect(relay.port, keylog);
  const slow = holds.map(h => request(c, h));
  await sleep(300);
  const q = c.request({ ':method': 'GET', ':path': '/queued', 'user-agent': 'test-client' });
  q.on('error', () => {});
  await sleep(150);
  q.close(http2.constants.NGHTTP2_CANCEL);       // reset while waiting for a free slot
  const rs = await Promise.all(slow);
  await sleep(300);
  c.close();
  await sleep(300);
  const rl = await stop(relay), ml = await stop(mock);
  fs.rmSync(keylog, { force: true });
  check(rs.every(r => r.status === 200), 'the eight slow streams answered');
  check(!RECEIVED.includes('GET /queued') && RECEIVED.length === 8,
        `server received only the eight (${JSON.stringify(RECEIVED.sort())})`);
  check(!ml.includes('/queued'), 'the cancelled request was never even shown to the proxy');
})();

// The server speaks first: an h2 server sends its SETTINGS as soon as its
// handshake ends (Cloudflare even in 0.5-RTT). A raw client that waits before
// its own preface makes sure those bytes reach ePtracer before the app's.
await (async () => {
  console.log('[h2-server-speaks-first]');
  const keylog = path.join(os.tmpdir(), `eptracer-h2-keylog-${process.pid}-e`);
  fs.writeFileSync(keylog, '');
  const mockPort = await freePort(), bridgePort = await freePort();
  const mock = await start('python3', [path.join(HERE, 'burp_style_proxy.py'), '--port', String(mockPort),
    '--cert', args['proxy-cert'], '--key', args['proxy-key'], '--upstream', `127.0.0.1:${bridgePort}`]);
  const relay = await start(args.relay, ['--upstream', String(SERVER_PORT), '--keylog', keylog,
    '--proxy-port', String(mockPort), '--bridge-port', String(bridgePort)]);
  RECEIVED.length = 0;

  const frame = (type, flags, stream, payload) => {
    const h = Buffer.alloc(9);
    h.writeUIntBE(payload.length, 0, 3); h[3] = type; h[4] = flags; h.writeUInt32BE(stream, 5);
    return Buffer.concat([h, payload]);
  };
  // HPACK: literal header field without indexing, new name, no Huffman
  const hpack = fields => Buffer.concat(fields.map(([n, v]) =>
    Buffer.concat([Buffer.from([0x00, n.length]), Buffer.from(n), Buffer.from([v.length]), Buffer.from(v)])));

  const result = await new Promise(resolve => {
    const s = tls.connect({ host: '127.0.0.1', port: relay.port, servername: AUTHORITY,
                            ca: fs.readFileSync(args.ca), ALPNProtocols: ['h2'] });
    s.on('keylog', line => fs.appendFileSync(keylog, line));
    let buf = Buffer.alloc(0), body = '', goaway = false, done = false;
    const finish = () => { if (!done) { done = true; s.destroy(); resolve({ body, goaway, alpn: s.alpnProtocol }); } };
    s.on('secureConnect', () => setTimeout(() => {
      s.write(Buffer.concat([
        Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
        frame(4, 0, 0, Buffer.alloc(0)),
        frame(1, 0x5, 1, hpack([[':method', 'GET'], [':scheme', 'https'], [':path', '/early'],
                                [':authority', AUTHORITY], ['user-agent', 'test-client']])),
      ]));
    }, 300));
    s.on('data', d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 9) {
        const len = buf.readUIntBE(0, 3), type = buf[3], flags = buf[4], stream = buf.readUInt32BE(5) & 0x7fffffff;
        if (buf.length < 9 + len) break;
        const payload = buf.subarray(9, 9 + len);
        buf = buf.subarray(9 + len);
        if (type === 4 && !(flags & 1)) s.write(frame(4, 1, 0, Buffer.alloc(0)));   // ACK SETTINGS
        if (type === 7) { goaway = true; finish(); }
        if (type === 0 && stream === 1) {
          body += payload.toString();
          if (flags & 1) finish();
        }
        if (type === 3 && stream === 1) finish();   // RST_STREAM
      }
    });
    s.on('error', finish);
    s.on('close', finish);
    setTimeout(finish, 8000);
  });

  await sleep(300);
  const rl = await stop(relay); await stop(mock);
  fs.rmSync(keylog, { force: true });
  check(result.alpn === 'h2', `h2 negotiated (${result.alpn})`);
  check(!result.goaway, 'no GOAWAY: the server session kept its SETTINGS');
  check(result.body.includes('"path":"/early"'), `answer from the real server reached the app (${result.body.slice(0, 60) || 'none'})`);
  check(JSON.stringify(RECEIVED) === '["GET /early"]', `server received it exactly once (${JSON.stringify(RECEIVED)})`);
  if (!result.body) console.log(rl.split('\n').filter(l => l.includes('[bridge]')).slice(-6).join('\n'));
})();

await scenario('h2-trailers', {
  expect: ['POST /trailers'],
  run: c => request(c, '/trailers', { method: 'POST', body: Buffer.from('\0\0\0\0\x05hello'),
                                      headers: { 'content-type': 'application/grpc', te: 'trailers' } }),
  asserts: r => {
    check(r.status === 200 && viaProxy(r), 'gRPC-style call through the proxy');
    check(r.trailers && r.trailers['grpc-status'] === '0', `trailers reached the app (${JSON.stringify(r.trailers)})`);
  },
});

server.close();
console.log(`\n${FAIL ? 'FAILED' : 'PASSED'} (${FAIL} failure${FAIL === 1 ? '' : 's'})`);
process.exit(FAIL ? 1 : 0);
