# Latency & overhead model — TLS Splice

Stato: **vivo** (si aggiorna con i numeri misurati) · Companion di
[`tls-splice-proxy.md`](tls-splice-proxy.md) · Data: 2026-10-29

Questo file è la base per **costruire i test** e **determinare la latenza** della soluzione.
Contiene (1) il modello di overhead, (2) le quantità da misurare, (3) gli esperimenti A/B e (4) la
tabella dei risultati da riempire. Gli script vivono in [`../../bench/`](../../bench/).

---

## 1. Principio: dove sta (e dove non sta) l'overhead

> Nel percorso SPLICE eBPF **non tocca il data path per-byte**. I byte applicativi li relaya
> l'userspace; eBPF interviene solo su `connect(2)` (una volta) e sulla cattura chiave (poche
> volte per handshake). L'overhead che scala col traffico è **crypto + copie userspace**.

Tre assi, da non confondere:

- **Per-connessione** (una tantum): handshake extra verso il proxy, hold in `AWAIT_KEYS`, trial
  decryption. Costo in **ms/connessione**, indipendente dal volume.
- **Per-byte** (scala col traffico): decifra + ricifra + copie del sandwich. Costo in **ns/byte**.
- **Risorse**: CPU (crypto), memoria (buffer per conn), **thread** (il limite di scala reale).

---

## 2. Modello analitico (da validare con i numeri misurati)

### 2.1 eBPF — per-connessione, atteso trascurabile

| Programma | Frequenza | Costo/hit atteso |
|---|---|---|
| `cgroup/connect4/6`, `getpeername/getsockname` | 1× per `connect(2)` | sub-µs |
| uprobe key-capture | 2–6× per handshake | ~1–2 µs (trap `int3`) |
| uretprobe `do_dlopen` (Android) | 1× per `dlopen` | ~2 µs + pausa SIGSTOP (ms, una tantum) |
| `iter/task_vma` (`--key-hunt`) | on demand | **secondi** (ultima risorsa) |

Misura di verità: `BPF_STATS` (`bpftool prog show`, cicli/run per programma).

### 2.2 Crypto per-byte — la voce dominante

Con AES-NI / SIMD, AES-128-GCM e ChaCha20-Poly1305 ~1–2 GB/s per core ⇒ ~**0.5–1 ns/byte per
passata**. Le passate dipendono dalla modalità (fast path del §7.2 del design):

| Modalità | Passate crypto/byte | Copie loopback |
|---|---|---|
| Fuori `--splice-scope` | **0** (inoltra ciphertext) | 1 relay |
| In scope, nessuna modifica | 1 (decifra per il proxy) + fast-path uscita | sandwich |
| In scope, request/response editata | 2 (decifra + ricifra) | sandwich |

Formula latenza per un messaggio di `B` byte:
`T ≈ T_setup(conn) + n_passate · c_crypto · B + n_hop · (c_copy · B + t_syscall)`
dove `c_crypto` ≈ ns/byte dal §4.1, `n_hop` = numero di attraversamenti userspace del sandwich.

### 2.3 Sandwich (copie + context switch) — per-byte + per-hop

Loopback ~decine di GB/s ⇒ la banda non è il collo di bottiglia; dominano syscall e scheduling
per hop (~10–50 µs/hop stimati). Da misurare isolando il proxy (echo origin, §3).

### 2.4 Memoria / thread

- Per connessione: 2 buffer di riassemblaggio + chiavi + 2 inflater nghttp2 (h2) ≈ **decine di
  KB/conn**.
- **Limite di scala**: `http_intercept.c` è thread-per-session; il sandwich raddoppia le gambe.
  Migliaia di conn concorrenti = migliaia di thread → tetto pratico qui, non sulla CPU.

---

## 3. Isolare le variabili

Il collo di bottiglia reale in uso è **il proxy** (Burp/Caido: parsing, history, Intercept
manuale), ordini di grandezza più lento del crypto. Per misurare l'overhead **di ePtracer** e non
del proxy:

1. **Origin locale** (`bench/origin_https.py`): HTTPS su loopback, risposta di taglia
   parametrica, zero logica → isola la rete.
2. **Proxy stile Burp mock** (`bench/burp_style_proxy.py`): CONNECT + MITM con CA propria,
   latenza ~0 e opzionale match/replace → "proxy stile Burp" senza l'overhead della GUI di Burp.
   Lo stesso test gira poi con Burp reale puntando lì il traffico.
3. Confronto **A/B** tra modalità (§5), ciascuna con lo stesso origin e lo stesso proxy mock.

---

## 4. Esperimenti

### 4.1 Microbench crypto (per-byte puro) — `bench/microbench_crypto.sh` + `bench/test_tls_record`

- `openssl speed -evp aes-128-gcm aes-256-gcm chacha20-poly1305` → GB/s di riferimento HW.
- `test_tls_record --bench` → ns/byte di **decifra** e **decifra+ricifra** attraverso il nostro
  `tls_record.c` reale (non la teoria): è il numero che entra nella formula §2.2.

### 4.2 Costo uprobe — `bench/microbench_uprobe.sh`

Loop stretto che invoca la funzione sondata N volte, con e senza probe attach → µs/hit. Confronto
con `bpftool prog show` (cicli/run).

### 4.3 Latenza end-to-end A/B — `bench/latency_ab.py`

Client che misura **TTFB** e **durata totale** per taglie di risposta `{1 KB, 64 KB, 1 MB, 10 MB}`
nelle modalità del §5, verso l'origin locale e il proxy mock. N ripetizioni → p50/p90/p99.

### 4.4 Throughput — `bench/latency_ab.py --throughput`

Download sostenuto per modalità → MB/s; evidenzia il recupero del fast path (0 passate fuori
scope).

### 4.5 Scala memoria/thread — `bench/scale_probe.sh`

C connessioni concorrenti crescenti → `VmRSS` e `Threads` da `/proc/<pid>/status`; curva fino al
degrado.

---

## 5. Matrice delle modalità da confrontare

| # | Modalità | Cosa isola |
|---|---|---|
| A | `direct` (nessun ePtracer) | baseline assoluta |
| B | `-H` solo (cattura read-only) | costo della sola osservazione via uprobe |
| C | `-I direct` (redirect, nessun proxy) | costo del solo redirect + relay |
| D | SPLICE passthrough (fuori scope, 0 passate) | costo sandwich senza crypto |
| E | SPLICE in scope, no edit (1 passata) | + decifratura |
| F | SPLICE in scope, edit (2 passate) | + ricifratura + seq divergenti |
| G | MITM classico (`-I` + CA) | confronto con l'approccio pre-esistente |

Overhead netti d'interesse: `E−D` = decifratura; `F−E` = ricifratura; `D−C` = sandwich;
`C−A` = redirect; `B−A` = osservazione.

---

## 6. Risultati misurati

> Da riempire eseguendo `bench/run_all.sh`. HW/kernel annotati per ogni run.

### 6.1 Crypto (§4.1)

Run 2026-10-29 · 12th Gen Intel i7-1260P, AES-NI · kernel 7.0.0-38-generic · OpenSSL 3.0.13
· `bench/run_tls_record.sh --bench` (`tls_record.c` reale, record da 64 KB — la taglia tipica
di un chunk applicativo, dove l'overhead fisso per-record è ammortizzato).

| Cipher | tls_record decifra (ns/byte) | decifra+ricifra (ns/byte) |
|---|---|---|
| AES-128-GCM | **0.28** | **0.31** |
| AES-256-GCM | **0.68** | **0.68** |
| ChaCha20-Poly1305 | **2.34** | **2.34** |

Note dai dati grezzi:
- Su record piccoli (1 KB) domina l'overhead fisso per-record (`EVP_CIPHER_fetch` + setup):
  AES-128-GCM ~1.3 µs/record. In produzione va **cachato** il `EVP_CIPHER`/`EVP_CIPHER_CTX` per
  connessione (TODO in `tls_record.c`): abbatte il costo dei messaggi piccoli, i più comuni per le
  API.
- ChaCha20 senza accelerazione HW dedicata è ~5–8× AES-GCM: su x86 con AES-NI conviene lasciare
  che il server negozi AES-GCM; su ARM senza AES esteso il rapporto si ribalta.
- **Criterio §7 rispettato**: il percorso no-edit aggiunge ~0.3 ns/byte (AES-128-GCM), ben sotto
  i 3 ns/byte target. Un corpo da 1 MB = ~0.3 ms di CPU crypto, invisibile accanto alla history
  del proxy.

### 6.2a Splice relay end-to-end, senza proxy — `bench/run_e2e_splice.sh --bench 300`

Run 2026-10-29 · stesso HW · client e server TLS 1.3 reali (Python `ssl` / OpenSSL 3.0.13),
loopback, richieste keep-alive, suite negoziata TLS_AES_256_GCM_SHA384. Chiavi dal keylog del
client (al posto della cattura eBPF). p50 / p99 in ms:

| Taglia risposta | direct | splice passthrough (fast path) | splice edit s2c (ricifra) |
|---|---|---|---|
| 1 KB | 0.069 / 0.213 | 0.069 / 0.424 | 0.049 / 0.220 |
| 64 KB | 0.060 / 0.073 | 0.160 / 0.347 | 0.234 / 0.519 |
| 1 MB | 2.582 / 4.658 | 2.726 / 5.035 | 3.530 / 5.340 |

Lettura:
- **Fast path**: +0.1 ms a 64 KB e +0.14 ms a 1 MB: è il costo della decifratura per
  l'osservazione più un hop userspace in più. A 1 KB non è distinguibile dal rumore.
- **Edit**: +0.95 ms su 1 MB, in linea col microbench §6.1 (AES-256-GCM ~0.7 ns/byte per la
  ricifratura, più le copie). Criterio §7 rispettato.
- **Lezione su Nagle**: senza `TCP_NODELAY` *tutte* le colonne, anche `direct`, mostravano un
  tetto di ~41 ms (Nagle + delayed ACK). Uno splice che riscrive i record li emette uno per
  uno, quindi senza `TCP_NODELAY` su entrambe le gambe la seconda scrittura aspetta l'ACK
  ritardato. **Requisito d'implementazione**: `TCP_NODELAY` su ogni socket del percorso. Il
  listener di `http_intercept.c` lo fa già su entrambe le gambe (dial e accept); il bridge
  (FRONT/UPSTREAM) e `splice_relay` lo devono fare allo stesso modo.
- Il campione 1 KB "edit < direct" è rumore di scheduling (sotto i 0.1 ms).

### 6.2 Latenza end-to-end (§4.3) — p50 / p99 (ms)

| Taglia | A direct | B -H | C -I direct | D passthrough | E no-edit | F edit | G MITM |
|---|---|---|---|---|---|---|---|
| 1 KB | | | | | | | |
| 64 KB | | | | | | | |
| 1 MB | | | | | | | |
| 10 MB | | | | | | | |

### 6.3 Scala (§4.5)

| Conn concorrenti | VmRSS (MB) | Threads | note |
|---|---|---|---|

---

## 7. Criteri di accettazione (target di progetto)

- Overhead per-byte in modalità E (no-edit) **< 3 ns/byte** aggiunti rispetto a C.
- `T_setup` per connessione **< 2 ms** su loopback (escluso RTT verso un proxy remoto).
- Nessuna connessione del target rotta da un fallimento dello strumento (degrado a OPAQUE).
- Fast path (D) indistinguibile da C entro il rumore di misura.
