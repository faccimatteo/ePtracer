# Contesto — richiesta originale

Questo file registra il prompt che ha originato il design in
[`tls-splice-proxy.md`](tls-splice-proxy.md), così da poter essere riusato come contesto in una
sessione futura.

## Prompt (verbatim)

> Analizza il contenuto di questa repository. Progetta il design di una feature che utilizzi
> solamente le features espose da eBPF (kernelside e userside) per recuperare il traffico da un
> binario black box. La vera sfida qui e l'obiettivo è prendere tutto il traffico https e
> reindirizzarlo verso un proxy in modo che sia ispezionabile e modificabile. Immagina che il
> traffico di passaggio dev'essere possibile da forwardare verso burpsuite o caido. L'obiettivo
> è quello di utilizzare il tool per analizzare il traffico HTTP/HTTPS di un binario offuscato,
> che esso sia binario linux o un app android o ios. Logga tutto questo prompt all'interno di un
> file in modo che può essere utilizzato come contesto nella prossima volta.

## Requisiti estratti dal prompt

- Usare **solo** feature eBPF (kernel side + user side).
- Recuperare il traffico da un **binario black box** (offuscato, codice non disponibile).
- Obiettivo centrale: prendere **tutto** il traffico HTTPS e reindirizzarlo a un proxy in modo
  **ispezionabile e modificabile**.
- Il traffico deve poter essere **forwardato verso Burp Suite o Caido**.
- Target: binario Linux, app Android, app iOS.
- **Loggare il prompt in un file** riutilizzabile come contesto (questo file).

## Note di contesto (stato al 2026-10-29)

- Repo: `ePtracer` (owner `faccimatteo`), analizzatore di processi eBPF per Linux/Android.
- Branch al momento della richiesta: `http-decoder` (main: `main`).
- Capacità già presenti rilevanti: cattura plaintext via uprobe TLS (`-H`), redirect in-path via
  `cgroup/connect4` verso proxy (`-I`), trust CA automatico per processi spawnati (`http_ca.c`).
- **iOS**: fuori portata perché XNU non espone eBPF — vincolo tecnico, non scelta di priorità.
  Dettagli in `tls-splice-proxy.md` §10.
- La feature progettata ("TLS Splice") risolve il caso del **certificate pinning**: non fa MITM
  ma decifra con le chiavi di sessione estratte dal processo e mette il proxy nel path tramite un
  "proxy sandwich". Vedi `tls-splice-proxy.md` §3 e §8.

## Ambito d'uso

Strumento per **testing di sicurezza autorizzato** (pentest, bug bounty, ricerca): da usare su
applicazioni di cui si ha diritto di analizzare il traffico.
