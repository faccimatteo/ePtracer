# Design: TLS Splice — traffico HTTPS di un binario verso Burp/Caido con il pinning attivo

Stato: **proposta** · Branch di partenza: `http-decoder` · Data: 2026-10-29
Contesto del prompt: [`PROMPT_CONTEXT.md`](PROMPT_CONTEXT.md)

> Strumento di analisi per testing di sicurezza autorizzato (pentest, bug bounty, ricerca). La
> feature va usata su processi/applicazioni di cui si ha il diritto di analizzare il traffico.

---

## 1. Obiettivo

Portare il traffico HTTP/HTTPS di un binario (ELF Linux o app Android) dentro un proxy
intercettante (Burp Suite, Caido, mitmproxy, ZAP) in modo che sia **ispezionabile e
modificabile** (Intercept, Repeater, Match & Replace), usando **solo** primitive eBPF, anche
quando l'applicazione fa certificate pinning.

Primitive ammesse:

- **kernel side**: uprobe/uretprobe, tracepoint, `tp_btf`, programmi `cgroup/*`
  (connect/sendmsg/getpeername/getsockname), iteratori BPF (`iter/task_vma`), helper di sola
  lettura (`bpf_copy_from_user_task`, `bpf_get_current_uid_gid`, `bpf_send_signal_thread`);
- **user side**: libbpf, ring buffer, mappe, più l'userspace esistente (socket, libcrypto per
  il record layer, nghttp2 per HTTP/2).

Vincoli: niente Frida/ptrace/`LD_PRELOAD`, niente patch dell'APK/ELF, niente installazione della
CA nello store di sistema, niente iptables/nftables, niente network namespace o VPN, niente
configurazione proxy lato applicazione.

### Non-obiettivi

- **iOS**: XNU non ha eBPF — nessuna di queste primitive esiste. Fuori portata per costruzione
  (vedi §10).
- HTTP/3 su QUIC nativo: si forza il fallback a TCP (§7.3); lo splice di QUIC è lavoro futuro.

---

## 2. Stato attuale della repo

| Componente | File | Cosa fa | Limite rispetto all'obiettivo |
|---|---|---|---|
| Cattura plaintext | uprobe SSL_*/PR_*/gnutls/wolfSSL/mbedTLS in `eptracer.bpf.c`, `tracers/http.c` | Legge il plaintext dentro il processo; il pinning è irrilevante | **Sola lettura**: niente edit/drop |
| Go TLS | `tracers/go_tls.c` | uprobe su `crypto/tls.(*Conn).Read/Write` | Serve la symtab |
| Riassemblaggio | `http_message.c`, `http2_message.c` | HTTP/1.x e HTTP/2 (HPACK via nghttp2) | — |
| Redirect in-path | `tracers/http_intercept.c`, `cgroup/connect4/6`, `getpeername4` | `connect(2)` → `127.0.0.0|(slot+2)`, poi `CONNECT host:443` verso il proxy | Proxy = MITM reale: col pinning l'handshake fallisce |
| Trust CA automatico | `http_ca.c`, `http_ca_detect.c` | Env (`SSL_CERT_FILE`…) per spawnati, `certutil` per NSS | Non vale per `-P`, né per Android, né contro il pinning |

**Il buco**: `-H` vede tutto ma non modifica; `-I` modifica ma rompe su pinning e CA non fidate.
Su un target che pinna, oggi non si può avere il proxy *nel path* **e** il chiaro.

---

## 3. Idea centrale: non fare MITM, ma decifrare con le chiavi dell'app

Il MITM classico fallisce perché il proxy presenta un *suo* certificato. Ma ePtracer è già
in-path a livello TCP (`cgroup/connect4`) e, con le uprobe, può leggere dall'interno del
processo i **segreti di sessione** che la libreria TLS deriva durante l'handshake.

1. L'handshake TLS passa **inalterato** tra app e server reale: certificato autentico, quindi
   pinning, Certificate Transparency, mTLS, ECH e channel binding restano soddisfatti.
2. Le uprobe catturano i *traffic secret* (TLS 1.3) o il *master secret* (TLS 1.2) nel momento
   della derivazione.
3. ePtracer, che sta già relayando i byte cifrati, li **decifra**, passa il plaintext al proxy,
   riceve il plaintext eventualmente modificato e lo **ricifra con le stesse chiavi** verso il
   server (e viceversa per le risposte).

La sessione TLS è una sola, condivisa; chi ha le chiavi può scrivere record validi in entrambe
le direzioni. L'unica cosa che diverge tra le due "gambe" è il **numero di sequenza** del record
(implicito nel nonce AEAD), che ePtracer traduce.

```
   app (pinning attivo)        kernel             ePtracer                       proxy
  ─────────────────────   ───────────────   ─────────────────────────────   ──────────────────
  connect(1.2.3.4:443) ─▶ cgroup/connect4 ─▶ splice listener (slot N)
  ClientHello ───────────────────────────────▶ inoltra invariato ─────────────────────────────▶ server
  ◀─────────── ServerHello + cert VERO ◀──────  inoltra invariato ◀────────────────────────────
     │ uprobe: CLIENT/SERVER_TRAFFIC_SECRET_0 ─▶ tls_secret_rb ─▶ key store
  AppData(c2s, seq a) ───────────────────────▶ decifra(seq a) ─▶ front ─▶ edit ─▶ upstream
                                               ricifra(seq s) ◀───────────────────────────────┘
                                                     └──────────────────────────────────────▶ server
```

Proprietà che il MITM non ha: pinning-proof (come `-H`) **e** modificabile (come `-I`); nessuna
CA da installare nell'app; funziona su `-P` e su Android.

---

## 4. Architettura

```
                           ┌──────────────────────── eptracer.bpf.c ────────────────────────┐
                           │ cgroup/connect4/6     redirect TCP (esistente)                  │
                           │ cgroup/getpeername4/6 + getsockname4/6  address restore         │
                           │ cgroup/sendmsg4/6     blocco UDP/443 → fallback TCP (opz.)      │
                           │ uprobe key-capture    (§5) ──────────▶ tls_secret_rb           │
                           │ uprobe dlopen-gate    (§6.2) ─────────▶ lib_load_rb            │
                           └─────────────────────────────────────────────────────────────────┘
                                         │ ring buffer / mappe
  ┌──────────────────────────────────────▼────────────────────────── userspace ─────────────┐
  │ tls_anchor.c   risoluzione dei punti di cattura (ELF, string-anchor, call-site)          │
  │ tls_keys.c     key store: (pid, client_random) → segreti; candidati + trial decryption   │
  │ tls_record.c   parser record, ClientHello/ServerHello, key schedule 1.2/1.3, AEAD        │
  │ tls_splice.c   macchina a stati per connessione, traduzione seq, KeyUpdate              │
  │ proxy_bridge.c front (client del proxy) + upstream (a valle del proxy)                   │
  │ http_intercept.c (esistente) → per connessione: SPLICE | MITM | PASSTHROUGH             │
  └─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Selezione della modalità per connessione

Va decisa **prima di inoltrare il ClientHello** (dopo non si torna indietro).
`--tls-mode auto|splice|mitm|passthrough` (default `auto`):

| Condizione al ClientHello | Modalità |
|---|---|
| Esiste un punto di key-capture armato per PID/UID (§5) | **SPLICE** |
| Nessun key-capture, processo spawnato con CA iniettata (`http_ca.c`) | **MITM** (comportamento attuale di `-I`) |
| Nessuno dei due | **PASSTHROUGH** cifrato + `-H` per la visibilità |
| Cleartext (nessun ClientHello) | relay HTTP verso il proxy come oggi |

In SPLICE, se le chiavi non arrivano entro `--key-timeout` (default 500 ms), la connessione
degrada a **OPAQUE**: record inoltrati cifrati (l'app continua a funzionare), connessione
marcata `NO-KEY` con l'SNI nel log. Principio: mai rompere il target per un limite dello
strumento.

---

## 5. Estrazione delle chiavi (kernel side)

Principio: **raccogliere candidati in modo largo, validarli crittograficamente**. Un segreto
sbagliato non produce output sbagliato: la verifica del tag AEAD fallisce e il candidato viene
scartato. Questo rende sicure le tecniche euristiche (offset dedotti, call-site) senza rischio di
falsi positivi.

Evento unico verso userspace:

```c
/* include/tls_keys.h */
struct tls_secret_event_t {
	__u64 timestamp_ns;
	__u32 pid, tid;
	__u64 ssl_ptr;           /* handle della connessione, se noto */
	__u8  source;            /* KEYSRC_GO, KEYSRC_BORING_LOGSECRET, KEYSRC_KEYLOG_CB, ... */
	__u8  label;             /* CLIENT_HS, SERVER_HS, CLIENT_TRAFFIC_0, SERVER_TRAFFIC_0,
	                            EXPORTER, TLS12_MASTER, EARLY */
	__u8  has_client_random;
	__u8  secret_len;        /* 32 (SHA-256) o 48 (SHA-384) per 1.3; 48 per 1.2 master */
	__u8  client_random[32];
	__u8  secret[64];
};
```

### 5.1 Matrice delle sorgenti (in ordine di preferenza)

| Stack | Punto di cattura | Note |
|---|---|---|
| **Go `crypto/tls`** | uprobe *entry* su `crypto/tls.(*halfConn).setTrafficSecret`; per 1.2 entry su `(*Config).writeKeyLog` | Solo entry probe (no uretprobe in Go, cfr. `go_tls.c`); argomenti in registri ABIInternal |
| **BoringSSL** (Conscrypt, Cronet, Flutter, Chromium) | entry di `ssl_log_secret(ssl, label, secret)` risolta per **string-anchor** (§5.2) | L'uprobe scatta *prima* del check "callback == NULL": non serve alcuna callback; `label` dice quale segreto |
| **OpenSSL 1.1.1 / 3.x** | entry di `nss_keylog_int` / `ssl_log_secret` se in `.symtab`; altrimenti string-anchor | Su libssl con solo `.dynsym` vale l'anchor |
| **rustls** | **call-site probe** sulla chiamata `key_log.log(label, client_random, secret)` (§5.2) | Dispatch dinamico: si sonda l'istruzione di call |
| **NSS** | `ssl3_RecordKeyLog` / `tls13_DeriveSecret` via anchor | Fallback già pronto: MITM + `certutil` |
| **mbedTLS** | callback di export key interna (`mbedtls_ssl_set_export_keys_cb` path) | Simboli spesso presenti nei firmware |
| **qualsiasi (ultima risorsa)** | `iter/task_vma` + `bpf_copy_from_user_task` (§5.4) | Costoso; per stack senza alcun aggancio |

Tutte le sorgenti primarie sono **di sola lettura** (uprobe su entry/call-site). Si veda §9 per
i limiti.

### 5.2 Risoluzione per *string-anchor* e *call-site probe* (`tls_anchor.c`)

Nei binari stripped i simboli interni mancano, ma ogni stack che supporta `SSLKEYLOGFILE`
contiene le **label NSS keylog** come costanti: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
`SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`,
`EXPORTER_SECRET`, `CLIENT_RANDOM`. Sono fissate dal formato, non dal vendor.

Algoritmo (solo lettura del file ELF, stessa filosofia di `go_tls.c`):

1. trovare l'indirizzo di ciascuna label in `.rodata`;
2. trovarne i riferimenti in `.text` (`lea reg,[rip+disp32]` su x86-64; `adrp`+`add` su arm64);
3. la prima `call`/`bl` successiva con la label nel registro giusto (`rsi`/`x1`) identifica la
   funzione di log → uprobe sulla sua entry. Se la call è **indiretta** (`blr`/`call reg`, tipico
   di rustls `dyn KeyLog`), uprobe **sull'istruzione di call**: lì i registri contengono già
   label, client_random e secret;
4. nessun attach se la decodifica non è coerente (principio "partial decode = no probe" già
   usato per i `RET` di Go — il length decoder di `go_tls.c` garantisce i confini di istruzione).

Se l'offuscatore cifra le stringhe, l'anchor sparisce: si passa a firme a byte della funzione
(database per versione di BoringSSL) e, in ultima istanza, al §5.4.

### 5.3 Correlazione segreto ↔ connessione

ePtracer vede sul filo `client_random` (ClientHello, in chiaro), `server_random` e la cipher
suite (ServerHello). Il key store indicizza:

1. per `(pid, client_random)` quando la sorgente lo fornisce (keylog line, Go `writeKeyLog`,
   rustls call-site) → match esatto;
2. altrimenti come **candidati** per `pid` in una finestra temporale (handshake ± 2 s). Al primo
   record applicativo si deriva `key`/`iv` (HKDF-Expand-Label) e si tenta l'apertura AEAD con
   seq 0: il tag verifica → match certo, costo trascurabile.

Lo stesso trial decryption individua il confine handshake/applicativo in TLS 1.3 senza decifrare
l'handshake: i record che non si aprono con la chiave applicativa a seq 0 sono ancora handshake
e vengono inoltrati invariati.

### 5.4 Key hunting in memoria (ultima risorsa, `--key-hunt`)

Per stack senza alcun aggancio (JSSE desktop, VM custom, stringhe cifrate): un iteratore
sleepable `iter/task_vma` filtrato sul PID cammina sulle VMA anonime scrivibili e, con
`bpf_copy_from_user_task`, copia finestre in un ring buffer; userspace filtra per
entropia/allineamento e tenta il trial decryption sul primo record. È costoso (secondi): adatto
a connessioni keep-alive o alla modalità "cattura ora, decifra dopo", non al percorso standard.

---

## 6. Copertura del target: Linux e Android

### 6.1 Linux (ELF)

Invariato: `-p` (spawn) o `-P` (attach), `-F` per i figli. Il key-capture si aggancia agli
stessi file già scoperti da `/proc/<pid>/maps`, più lo string-anchor scan sull'eseguibile
principale (TLS statico, Go stripped, rustls). Bonus: il limite "Go serve la symtab" si chiude
recuperando i nomi da `.gopclntab` (presente anche negli stripped) — sblocca `go_tls.c` e
`setTrafficSecret`.

### 6.2 Android (rooted, kernel GKI con BTF, eadb)

- **Filtro per UID** invece che per PID: `--uid <uid>` / `--package com.example.app` (UID da
  `/data/system/packages.list`). In kernel `bpf_get_current_uid_gid()` filtra ogni programma.
  Copre tutti i processi dell'app (incluso `:remote`) senza dipendere dalla fork da zygote.
- **Gating all'avvio**: probe e programmi cgroup armati *prima* di `am start`, così la prima
  connessione è già coperta.
- **Librerie a runtime** (`libflutter.so`, Cronet): uretprobe su `__loader_dlopen` e
  `__loader_android_dlopen_ext` del `linker64` di bionic → il pid va a userspace, che ferma il
  processo con `bpf_send_signal(SIGSTOP)`, scansiona i nuovi oggetti mappati e lo riavvia con
  `SIGCONT`. Pausa di pochi ms, nessuna connessione persa.
- **Librerie dentro l'APK** (`extractNativeLibs=false`): in `/proc/<pid>/maps` compaiono come
  `base.apk` a un offset; lo scanner legge l'ELF a quell'offset (`tls_anchor_find_at`) e la uprobe
  va posta su `base.apk` all'offset sommato.
- Conscrypt (`/apex/com.android.conscrypt/lib64/libssl.so`) è condivisa: una sola uprobe sulla
  funzione di keylog (anchor) con filtro UID copre OkHttp, Retrofit, `HttpURLConnection`, RN; su
  Maps/GMS anche Cronet usa la Conscrypt di sistema.
- Proxy: `adb reverse tcp:8080 tcp:8080` verso il proxy, `adb forward tcp:8082 tcp:8082` per il
  suo upstream; il bridge (§8) ascolta nel chroot eadb.
- Coesistenza con netd: i programmi cgroup di Android ci sono già → attach con
  `BPF_F_ALLOW_MULTI` come oggi.

**Verifier GKI 5.10.** Il verifier dei kernel GKI 5.10 è molto più severo di quello desktop e
ha richiesto correzioni (tutte valide anche su desktop), senza le quali i programmi non caricano:
- `-D_GNU_SOURCE` nella build, altrimenti `memmem` è implicito e il valore di ritorno a 64 bit
  viene troncato sulla glibc del dispositivo → lo scanner ELF fallisce in silenzio;
- le dimensioni passate a `bpf_probe_read_user` (keylog, `submit_http_chunk`) perdono il loro
  limite attraverso spill/reload: vanno fissate con `barrier_var` + maschera su potenza di due;
- il loop delle porte di `connect4/6` va mascherato con `barrier_var` (il compilatore lo renderebbe
  un cammino a puntatore limitato solo da `port_count`);
- le scritture consecutive su `ctx->user_ip6` in `connect6` vanno fatte su una copia fresca del
  contesto, o il compilatore le fonde su `ctx+offset` (rifiutato);
- il `.bpf.o` va compilato con `ARCH` corretto (`arm64`), altrimenti `PT_REGS_PARM*` usa i campi
  `pt_regs` x86 e le relocation CO-RE falliscono a runtime; una build pulita (`make clean`) evita
  artefatti stantii.

Il caricamento è reso resiliente: solo i programmi che servono alla modalità richiesta vengono
caricati (pura modalità splice non carica la cattura cleartext/Go di `-H`).

**Verificato sul campo** (Pixel 7a, Android 14, GKI 5.10): Google Maps (Cronet, HTTP/2,
certificate pinning) spliceato attraverso Caido — 33 richieste decifrate e consegnate una volta
ciascuna, pinning intatto, QUIC ricaduto su TCP, chiavi dalla Conscrypt trovata via `--package`.

| Stack app | Key source |
|---|---|
| Java/Kotlin (OkHttp, Volley, HttpURLConnection) | Conscrypt → BoringSSL anchor |
| Flutter | BoringSSL statico in `libflutter.so` → anchor |
| Cronet / WebView | BoringSSL statico → anchor |
| React Native | OkHttp → Conscrypt |
| Unity / C++ con OpenSSL o mbedTLS | anchor OpenSSL / mbedTLS |
| Go mobile | `setTrafficSecret` (gopclntab) |
| Rust (rustls) | call-site probe |

---

## 7. Record layer in userspace (`tls_record.c`, `tls_splice.c`)

### 7.1 Macchina a stati per connessione

```
 NEW ──ClientHello──▶ HANDSHAKE ──ServerHello(suite,ver)──▶ AWAIT_KEYS ──chiave validata──▶ SPLICED
                                              key-timeout └──────────────────────────────▶ OPAQUE
```

- **HANDSHAKE**: record inoltrati byte per byte; si parsano solo ClientHello/ServerHello
  (riuso di `intercept_tls_sni`).
- **AWAIT_KEYS**: i record handshake passano; il primo record applicativo di ciascuna direzione
  viene trattenuto finché la chiave non è nota (latenza del ring buffer: microsecondi).
- **SPLICED**: decifra → plaintext al bridge → plaintext di ritorno → ricifra.

### 7.2 Traduzione dei numeri di sequenza

Per direzione due contatori: `seq_in` (gamba letta) e `seq_out` (gamba scritta); chiave e IV sono
gli stessi su entrambe.

- TLS 1.3 / 1.2-AEAD con nonce implicito (ChaCha20-Poly1305): `nonce = iv XOR seq`.
- TLS 1.2 AES-GCM: nonce esplicito di 8 byte per record, ePtracer genera il proprio.
- TLS 1.2 CBC: si ha anche la MAC key dal key block; il seq entra nel MAC → stessa traduzione.
- **Fast path**: finché il plaintext non cambia e i confini dei record restano uguali, i
  contatori coincidono e si inoltra il ciphertext originale senza ricifrare. Alla prima modifica
  le gambe divergono e da lì si ricifra sempre.
- **KeyUpdate** (TLS 1.3): visto nel canale cifrato, inoltrato ricifrato, segreto ruotato in
  autonomia con `HKDF-Expand-Label(secret,"traffic upd","",Hash.length)` — nessun nuovo evento.
- **NewSessionTicket / alert / close_notify**: inoltrati ricifrati col seq tradotto.
- **0-RTT**: decifrato con `CLIENT_EARLY_TRAFFIC_SECRET` se catturato, altrimenti opaco.
- **Rinegoziazione 1.2**: rara → OPAQUE.

Crittografia con OpenSSL EVP (già linkato): `EVP_KDF` HKDF/TLS1-PRF, `EVP_aes_*_gcm`,
`EVP_chacha20_poly1305`, `EVP_aes_*_cbc` + HMAC.

### 7.3 QUIC e IPv6

- `cgroup/connect4/6`+`sendmsg4/6` per UDP: rifiuto dei datagrammi UDP/443 del target → Chrome,
  Cronet, OkHttp con QUIC ricadono su TCP+TLS. Flag `--block-quic` (default on in `splice`).
- IPv6: il limite attuale (`IPV6_V6ONLY`) richiede uno slot encoding su spazio loopback v6;
  fuori dallo scope minimo.

---

## 8. Integrazione con Burp/Caido: il "proxy sandwich" (`proxy_bridge.c`)

Dopo la decifratura ePtracer ha il plaintext, ma il proxy deve poterlo **modificare** senza
aprire lui la connessione verso il server (quella esiste già: è la sessione dell'app). Soluzione:
ePtracer sta **sia davanti sia dietro** al proxy.

```
 splice(plaintext app) ─▶ FRONT ──CONNECT host:443 + TLS(CA del proxy)──▶ proxy ──▶ UPSTREAM ─▶ splice ─▶ server
 app ◀─ splice ◀──────── FRONT ◀──────────────────────────────────────── proxy ◀── UPSTREAM ◀── splice ◀── server
```

- **FRONT**: per ogni connessione splice apre verso il proxy `CONNECT <authority>:443` + TLS.
  ePtracer è il client → fidarsi della CA del proxy è banale (la recupera già `http_ca.c`).
  L'authority viene dal plaintext (`Host` / `:authority`): affidabile anche con ECH.
- **UPSTREAM**: listener che il proxy usa come *upstream proxy* (Burp: Settings → Network →
  Connections → Upstream proxy; Caido: Upstream Proxies). Riceve `CONNECT host:<porta>`, termina il
  TLS del proxy con un certificato di ePtracer e legge la richiesta **dopo** le modifiche.
- **Correlazione dei flussi, senza toccare la richiesta**: ogni richiesta va al proxy come
  `CONNECT host:<una porta solo sua>`. Il proxy apre il suo upstream verso la stessa destinazione,
  quindi la porta chiesta a UPSTREAM identifica la richiesta, anche se il proxy riusa o
  moltiplica le connessioni. Una porta torna libera solo dopo 30 minuti e mai mentre la sua
  richiesta è in attesa: una copia tardiva può indicare solo la propria richiesta, che la
  rifiuta. Effetto visibile: in Burp il target ha quella porta invece di `:443`.
- **Risposte**: la risposta reale del server, decifrata, è servita da UPSTREAM al proxy →
  Intercept sulla risposta → arriva a FRONT → ricifrata verso l'app. L'app riceve esattamente
  ciò che il proxy ha rilasciato.
- **Drop**: se il proxy scarta la richiesta, UPSTREAM non la vede e FRONT propaga la chiusura
  all'app (stessa semantica di `-I` oggi).
- **HTTP/2**: ePtracer termina h2 su entrambe le gambe con nghttp2 (già linkata); verso il proxy
  h1.1 o h2 (`--bridge-h2`). Le frame di controllo sono gestite per gamba, così una modifica di
  lunghezza del body non desincronizza il flow control. L'ALPN negoziato resta quello reale.
- **WebSocket**: dopo il `101`, FRONT/UPSTREAM diventano relay di byte; il proxy vede e modifica
  i messaggi nella sua tab WS.
- **Non-HTTP su TLS**: niente proxy, relay decifrato con log in `--http-chunks`.
- **Scope**: `--splice-scope <regex authority>`; fuori scope si resta nel fast path (ciphertext
  invariato), così la telemetria non intasa la history.

Variante senza upstream proxy: listener dedicato del proxy con "Redirect to host/port" verso
UPSTREAM + "Force use of TLS". Utile per tool che non supportano l'upstream proxy.

### 8.1 Garanzia: ogni richiesta arriva al server al massimo una volta

Requisito (2026-10-29): il server non deve **mai** ricevere più di una volta una richiesta
dell'app. Una seconda copia di una richiesta non idempotente (pagamento, creazione, cambio
password) romperebbe l'integrità che il protocollo stateless presuppone. È implementato in
`tracers/splice_bridge.c` e verificato da `bench/run_e2e_sandwich.sh`, che usa come oracolo il
server reale (conta le richieste ricevute).

- Ogni richiesta ha uno stato: `PENDING` (consegnata al proxy) → esattamente uno tra
  `DELIVERED`, `DROPPED` (il proxy ha risposto all'app senza inoltrarla), `ABANDONED` (l'app è
  sparita prima della decisione).
- Solo una richiesta `PENDING` può essere consegnata. Transizione e scrittura verso il server
  avvengono sotto lo stesso lock (`bridge_deliver()`), l'unico punto del codice che può farla
  arrivare al server. Se la scrittura fallisce a metà, la richiesta resta `DELIVERED` e non
  viene mai ritentata.
- Rifiuti verso il proxy: `409` già consegnata (Repeater, retry); `410` scartata o abbandonata
  (inoltro tardivo); `400` porta mai assegnata (target modificato).
- Ciò che non si può taggare (non HTTP/1.x, dopo un `101`) passa una volta senza proxy,
  oppure, con `strict`, la connessione viene chiusa.
- Record del client che nessuna chiave apre ancora: attesa fino a `hold_ms`. I record di
  handshake si riconoscono con la chiave di handshake e passano; con `strict` il resto chiude la
  connessione invece di passare non ispezionato.
- Smuggling: `Content-Length` doppi e in conflitto vengono rifiutati dal framer
  (`http1_frame.c`), perché il server potrebbe leggerli come due richieste.

"Al massimo" e non "esattamente": Drop e app che rinuncia producono volutamente zero
consegne. Un retry che l'app fa *da sé* su una nuova connessione è una richiesta nuova dell'app,
come senza proxy.

**Scartata**: la modalità "terminata", in cui Burp apre una propria connessione verso il server.
La richiesta arrivava una volta sola, ma non sulla sessione dell'app (rompe mTLS e session
binding), e si perdeva il controllo del punto di consegna.

### 8.2 HTTP/2

Un'app che ha negoziato h2 col server multiplexa le richieste e comprime gli header con HPACK,
il cui stato copre l'intera connessione: i suoi frame non si possono modificare e inoltrare. ePtracer
termina quindi HTTP/2 su **entrambe** le gambe della sessione TLS dell'app
(`tracers/splice_bridge_h2.c`, con nghttp2):

- verso l'app è una sessione h2 **server**: ogni stream diventa una richiesta HTTP/1.1 per il
  proxy, che percorre la stessa strada at-most-once di §8.1;
- verso il server è una sessione h2 **client** sulla stessa sessione TLS: la richiesta rilasciata
  dal proxy diventa un nuovo stream. Il preface e i SETTINGS dell'app restano alla sessione
  lato app; il server riceve quelli di ePtracer;
- le risposte tornano **per stream id**: una risposta tardiva non può finire su un'altra
  richiesta, quindi in h2 un timeout non obbliga a chiudere la connessione;
- `RST_STREAM` dall'app marca solo quello stream `ABANDONED`. Se era ancora in coda, il proxy
  non lo vede nemmeno;
- conversione: pseudo-header ↔ start line e `Host`; `cookie` multipli uniti con `"; "`
  (RFC 9113 §8.2.3); campi hop-by-hop rimossi; `Content-Length` ricalcolato dal body reale;
  trailer di risposta (`grpc-status`) portati come trailer chunked in HTTP/1.1.

### 8.4 Connessioni verso il proxy

Ogni richiesta viaggia verso il proxy su **una connessione FRONT tutta sua**, chiusa dopo la
risposta. Le connessioni non vengono mai riusate: un proxy HTTP/1.1 può chiudere una connessione
quando vuole (Burp lo fa con Discord, spesso senza annunciarlo), e non ci si ritrova mai a
scrivere su una connessione che sta morendo. La risposta su una connessione è per forza quella
della sua richiesta, quindi non serve nessun ordinamento. In HTTP/2 viaggiano fino a 8 richieste
in parallelo; in HTTP/1.1 una alla volta, perché lì le risposte devono arrivare all'app in ordine.

Se il proxy chiude una connessione senza rispondere:
- **richiesta già consegnata**: l'app riceve la risposta vera del server, che UPSTREAM tiene da
  parte finché l'app non ne ha una (il proxy l'ha vista passare);
- **non consegnata**: viene rimandata dopo 300 ms (se il proxy la inoltra nel frattempo, vale il
  caso precedente; una seconda copia verrebbe comunque rifiutata), al massimo 3 volte, poi `502`.

Le richieste che l'app annulla mentre aspettano uno slot libero non vengono mostrate al proxy.

### 8.3 WebSocket

Dopo il `101` la connessione porta due flussi di byte, entrambi attraverso il proxy, senza
parsing né etichette:

- app → FRONT → proxy → UPSTREAM → server: la connessione UPSTREAM che ha consegnato l'upgrade,
  quando vede passare il `101` del server, diventa un relay dedicato (`bridge_ws_relay()`);
- server → UPSTREAM → proxy → FRONT → app: ciò che il server manda subito dietro il `101` (lo
  `HELLO` del gateway di Discord) segue lo stesso percorso e resta in ordine.

Il proxy vede, trattiene e modifica i messaggi come per qualsiasi WebSocket. La consegna unica
resta valida: il flusso è uno solo, e un nuovo upgrade verso la stessa porta viene rifiutato
(`409`).

**Non ancora coperto**: WebSocket su h2 (extended CONNECT, rifiutato con `REFUSED_STREAM`;
Chromium usa comunque HTTP/1.1 per i WebSocket); trailer di *richiesta*; un pool di connessioni
FRONT per togliere l'head-of-line.

---

## 9. Limiti, osservabilità e sicurezza operativa

- **Percorso primario di sola lettura**: tutte le key source di §5.1 usano uprobe su
  entry/call-site, senza scrivere nella memoria del processo. Una variante con scrittura
  (iniezione di una keylog-callback via `bpf_probe_write_user`) è *esplicitamente esclusa dal
  default*: `bpf_probe_write_user` è vietata sotto kernel lockdown (Secure Boot) e lascia traccia
  in dmesg. Resterebbe eventualmente dietro un flag `--allow-write` documentato, ma non è parte
  della proposta minima.
- **Ciò che il tool non nasconde**: le uprobe inseriscono breakpoint software nella `.text`
  (visibili a un controllo d'integrità attivo del processo), e la connessione verso loopback
  compare in `/proc/<pid>/net/tcp`. Questo è documentato onestamente: ePtracer è uno strumento di
  analisi, non di evasione, e non tenta di ingannare meccanismi anti-tamper del target oltre al
  ripristino dell'indirizzo peer già fatto da `getpeername4` (necessario perché l'app funzioni).
- **Mai rompere il target**: ogni fallimento (chiave assente, stack ignoto, QUIC non
  degradabile) ricade su OPAQUE/passthrough, non su una connessione interrotta.
- **Degrado del pinning**: se la cattura chiave fallisce ma `-H` è attivo, il plaintext resta
  comunque visibile dall'interno (read-only), distinguendo "pinning" da "setup CA mancante".
- **Trial decryption come rete di sicurezza**: nessun segreto errato può produrre output errato;
  il tag AEAD è il filtro.

---

## 10. iOS: perché non è coperto

XNU non ha eBPF: niente uprobe, niente cgroup hook, niente ring buffer. L'analogo su iOS passa da
Frida/`DYLD_INSERT_LIBRARIES`/jailbreak — approcci esplicitamente fuori dai vincoli di questo
design e di ePtracer. Nessun percorso di porting è previsto.

---

## 11. Piano di implementazione incrementale

1. **`tls_anchor.c`** — string-anchor scan (BoringSSL/OpenSSL) su un `libssl.so` di test;
   emette gli offset da sondare. Verificabile isolatamente contro `SSLKEYLOGFILE`.
2. **Key capture + `tls_keys.c`** — uprobe su `ssl_log_secret`, confronto dei segreti catturati
   con l'output di `SSLKEYLOGFILE` reale (ground truth). Nessun record layer ancora.
3. **`tls_record.c`** — decifratura offline: dato un pcap + i segreti catturati, ricostruire il
   plaintext e confrontarlo con `-H`. Chiude la correttezza di AEAD/HKDF/seq.
4. **`tls_splice.c` + `proxy_bridge.c`** — splice live con `--tls-mode splice` su `curl`
   (OpenSSL) verso mitmproxy; prima sola lettura, poi edit.
5. **HTTP/2 bridge**, poi **Go** (`setTrafficSecret` + gopclntab), **rustls** (call-site),
   **Android/Conscrypt** (filtro UID + dlopen-gate).
6. **Stack residui** (mbedTLS, NSS) e, se serve, `--key-hunt`.

Ogni fase ha un oracolo di verità (`SSLKEYLOGFILE`, `-H`, pcap) che rende i test deterministici.
