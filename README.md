<h1 align="center">mitmcloak</h1>

<p align="center">
<b>Intercept the traffic. Keep the fingerprint.</b>
</p>

<p align="center">
Your browser behind mitmproxy runs the site's JavaScript and produces genuine telemetry.<br>
That half was never broken. The telemetry then leaves over a <b>Python TLS handshake</b>,
and the origin sees a browser that handshakes like a Python script.
</p>

<p align="center">
  <a href="https://pypi.org/project/mitmcloak/"><img src="https://img.shields.io/pypi/v/mitmcloak?color=2b7489&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/mitmcloak/"><img src="https://img.shields.io/pypi/pyversions/mitmcloak" alt="Python"></a>
  <a href="https://github.com/sardanioss/mitmcloak/actions"><img src="https://github.com/sardanioss/mitmcloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<br>

## Results

Headless Chromium fetching the same page, three ways. One line of difference in how
mitmproxy was started.

```diff
  JA4
  Chromium, direct          t13d1516h2_8daaf6152771_806a8c22fdea
- through mitmproxy         t13d2812h2_a01be8c064b6_0d46a1bf4a7c
+ through mitmcloak         t13d1516h2_8daaf6152771_806a8c22fdea
```

```diff
  Akamai HTTP/2

  Chromium, direct
    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
- through mitmproxy
-   1:4096;2:0;4:2147483647;5:131072;8:0;3:100;6:65536|2147418112|0|m,s,p,a
+ through mitmcloak
+   1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

A static match is the easy half. Chromium also reshuffles its TLS extensions on every
connection, so its JA3 moves while its JA4 holds still:

```diff
  Four connections, one browser
  Chromium, direct          4 distinct JA3   ·   1 JA4
+ through mitmcloak         4 distinct JA3   ·   1 JA4
```

It reproduces the behaviour, not one sample of it.

> mitmcloak does not defeat challenges. It stops the proxy corrupting a session that was
> already legitimate.

## How

```text
client  ──▶  mitmproxy + mitmcloak  ──▶  origin

             1.  read the client's ClientHello and HTTP/2 preface
             2.  mint an httpcloak preset from them, at runtime
             3.  serve that same request through it
```

No capture phase and no guessing: the client's real handshake is read on the way in and
replayed on the way out, in the same request cycle.

## Install

```bash
pip install mitmcloak
python -m mitmcloak install     # writes ~/.mitmproxy/config.yaml, then gets out of the way
mitmdump                        # plain mitmdump, no -s flag
```

`mitmdump`, `mitmweb` and the TUI keep every one of their own flags. `python -m mitmcloak
uninstall` puts it back. Prefer explicit? `mitmdump -s "$(python -m mitmcloak path)"`.

## What survives the proxy

| | mirrored |
|---|---|
| **TLS** | raw ClientHello byte for byte · GREASE in position · `X25519MLKEM768` key shares · extension order redrawn per handshake · resumption-shaped hello · extensions httpcloak has no model for |
| **HTTP/2** | SETTINGS values and their order · connection WINDOW_UPDATE · pseudo-header order · stream priority |
| **Headers** | order, casing and repeated names verbatim · per-request order · response trailers |

Measured against six clients, each compared direct and through the proxy. `exact` means
byte-identical, not "close enough".

| client | JA4 | JA3N | Akamai H2 |
|---|:---:|:---:|:---:|
| curl | exact | exact | exact |
| Chrome | exact | exact | exact |
| Firefox | exact | exact | exact |

## HTTP/3

A proxy setting only redirects TCP, so a client speaking QUIC never reaches the proxy at
all. That is why an app can keep working normally while mitmproxy shows nothing from it.
`wireguard` and `transparent` carry UDP, so QUIC from a device arrives; `reverse:http3://`
works for a fixed origin.

```bash
mitmdump --mode wireguard --set mitmcloak_http_version=h3
mitmdump --mode reverse:http3://example.com --set mitmcloak_http_version=h3
```

The request is bridged: the QUIC hello is captured, a preset is minted from it, and the
upstream leg goes out over HTTP/3 (`bridged=1 mirrored=1`, response `ver=3`).

**The h3 leg is not yet mirrored on the wire.** httpcloak resolves a preset's captured
hello in its HTTP/1.1 and HTTP/2 transports only; the QUIC transport never consults it.
Measured against `tls3.peet.ws` over h3, with curl as the client:

```text
curl, direct              q13d313_55b375c5d22e_19cb63ff0383   13 extensions
through mitmcloak         q13d37_55b375c5d22e_4ca1098a2eeb     7 extensions
```

Six extensions are missing rather than reordered: `compress_certificate`,
`ec_point_formats`, `encrypt_then_mac`, `extended_master_secret`, `post_handshake_auth`
and `psk_key_exchange_modes`. The cipher hash agrees because every QUIC client offers the
same three TLS 1.3 suites, so that half proves nothing. JA3 is also frozen across
connections where a real client rotates.

So h3 today gives you interception and an HTTP/3 upstream, not the client's fingerprint.
mitmcloak logs a warning when you turn it on rather than reporting a mirror it cannot
deliver. Use TCP where the fingerprint is what matters, until httpcloak wires the raw
hello into its QUIC transport.

**Use `http3://`, not `quic://`.** They are different mitmproxy schemes. `quic://` is a
raw QUIC tunnel with no HTTP parsing, so no request hook fires and nothing is bridged at
all: `captured_hellos=1` and no `bridged`, where `http3://` gives `bridged=1 mirrored=1`.

## Any client, any language

It is a proxy, so what sits in front of it is unconstrained. A Go or Rust service gets
Chrome's TLS and HTTP/2 fingerprints by setting one environment variable and integrating
nothing. That is wider reach than httpcloak has on its own, which is Python, Node, .NET
and the C library.

```bash
Go    http.Transport{Proxy: …}     Rust  reqwest .proxy()
Java  -Dhttp.proxyHost             Node  HTTPS_PROXY=…
curl · PHP · Ruby · C# · a browser · a phone · an app
```

Two limits are the proxy's rather than mitmcloak's: a client speaking QUIC/HTTP3 bypasses
an HTTP proxy entirely, and a client that pins certificates will not trust the CA.

---


<details>
<summary><b>Mirror mode, and keeping what it sees</b></summary>
<br>

By default mitmcloak reads the fingerprint of whatever client connected and reproduces it
upstream. Point it at your phone, and the origin sees **your phone**, not a preset someone
guessed.

It reads the client's raw ClientHello from mitmproxy's `tls_clienthello` hook and its HTTP/2
preface from `next_layer`, builds an httpcloak preset on the fly, and serves that same
request through it. One request cycle, no capture phase.

Measured against six clients, each compared direct and through the proxy:

| client | JA4 | JA3N | Akamai H2 |
|---|---|---|---|
| curl | exact | exact | exact |
| Chrome | exact | exact | exact |
| Firefox | exact | exact | exact |

Cost: about 2.6 ms once per *distinct* fingerprint, because preset names are
content-addressed. It does not show up in the latency budget.

### Catalogue everything that goes past

Mirroring only builds presets for clients we actually serve. Most of what a proxy sees is
not that: a pinned app that refused the certificate, a background agent that made one
request and left, a client that hung up. Those fingerprints are worth keeping too.

```bash
mitmdump --set mitmcloak_catalogue_dir=./seen
```

Every distinct TLS fingerprint observed lands there, used or not, with what was seen
alongside it:

```jsonc
{
  "version": 1,
  "preset": { "name": "observed-aa12047efcd3", "based_on": "chrome-151-ios", "tls": {...} },
  "_observed": {
    "hosts": ["gateway.icloud.com", "support.apple.com"],
    "connections": 22, "requests": 0,
    "rejected_our_certificate": 22,
    "connections_without_a_request": 22,
    "tls_only": true,
    "grease": true, "alpn": ["h2", "http/1.1"]
  }
}
```

Those files are **valid preset documents**, so anything the proxy watched can become a
preset with no conversion:

```python
httpcloak.load_preset("seen/observed-aa12047efcd3.json")
```

The `_observed` block rides alongside and is ignored on load. `tls_only: true` means only
the TLS half was captured, because the connection never got far enough to show its HTTP/2
preface, so that layer comes from `based_on`.

`mitmcloak.catalogue` lists what has been seen and `mitmcloak.catalogue.save <dir>` writes
it out on demand.

### Keep a fingerprint without keeping the device

```bash
mitmdump --set mitmcloak_export_dir=./presets
```

Every mirrored client is written out as a portable httpcloak preset. Load it anywhere,
with no proxy and no device:

```python
import httpcloak
name = httpcloak.load_preset("presets/mc-5dd29ec437e7.json")
httpcloak.Session(preset=name).get("https://example.com/")
```

Set the phone up once, export, then run from anywhere.

</details>

<details>
<summary><b>Configuration and the four tiers of control</b></summary>
<br>

Every option works from the command line and from mitmweb's option editor, where the ones
with a fixed set of values render as dropdowns.

```bash
mitmdump --set mitmcloak_preset=chrome-151-windows \
         --set mitmcloak_mode=auto \
         --set mitmcloak_headers=merge
```

| option | default | what it does |
|---|---|---|
| `mitmcloak_preset` | `chrome-151-windows` | preset used when not mirroring |
| `mitmcloak_mode` | `auto` | `auto` mirrors when it can and falls back; `static` never mirrors; `mirror` refuses to fall back |
| `mitmcloak_headers` | `merge` | `merge` keeps the client's values inside the preset's block; `replace` keeps only semantic headers; `exact` sends the client's block verbatim and nothing else |
| `mitmcloak_rule` | | per-flow preset, repeatable, first match wins |
| `mitmcloak_bypass` | | flow filter for requests that should not be bridged |
| `mitmcloak_preset_file` | | JSON preset to load at startup, repeatable |
| `mitmcloak_session_scope` | `origin` | `origin`, `client` or `connection`, see below |
| `mitmcloak_export_dir` | | write every mirrored preset here |
| `mitmcloak_http_version` | `auto` | `auto`, `h1`, `h2`, `h3` |
| `mitmcloak_max_sessions` | `96` | upstream session pool cap, and the main memory dial (see below) |
| `mitmcloak_max_body` | `50 MB` | larger requests are handed back to mitmproxy |
| `mitmcloak_proxy` | | upstream proxy for the httpcloak leg |
| `mitmcloak_ja3` / `mitmcloak_akamai` | | one-off fingerprint overrides |
| `mitmcloak_tcp_ttl` / `_mss` / `_window_size` | | TCP/IP knobs |
| `mitmcloak_catalogue_dir` | | record every fingerprint seen, used or not |
| `mitmcloak_identify_by_tls` | `true` | pick a mirrored client's base from its TLS stack, falling back to the User-Agent |
| `mitmcloak_timeout` | `30` | upstream request timeout, seconds |
| `mitmcloak_verify` | `true` | verify upstream certificates |
| `mitmcloak_max_idle` | `300` | seconds before an idle upstream session is swept |
| `mitmcloak_disable_ech` | `false` | disable Encrypted Client Hello upstream |
| `mitmcloak_tls_only` | `false` | keep the preset's TLS but not its headers |

### Header modes

`merge` and `replace` hand httpcloak a dict, and a dict cannot hold two `Cookie` headers
or remember that the client wrote `X-FOO`. `exact` hands over ordered pairs instead:
order, casing and repeated names all survive, and httpcloak adds nothing of its own.

Measured through the proxy, the same curl request with `Cookie: a=1`, `X-ODD-CASE: 1`,
`Cookie: b=2`:

```text
merge   Host, Connection, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile,
        Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Accept-Encoding,
        Accept-Language, Cookie, X-Odd-Case
exact   Host, Cookie, X-ODD-CASE, Cookie, User-Agent, Accept
```

`Host` is protocol framing that httpcloak writes itself. Everything after it in the
second line is exactly what the client sent, both `Cookie` headers included, in their
original interleaved positions.

The trade is that `exact` discards the preset's header block entirely, so it is right
when the client in front of the proxy *is* the client you are impersonating, and wrong
when it is not. Mirror mode is the case it was built for. Under a static preset, `merge`
stays the better answer.

In `merge` and `replace` the client's header order is sent alongside the dict, but only
when the preset was mirrored from that same client, for the same reason.

### Per-flow rules, in mitmproxy's own filter language

Not a syntax invented here, so `~d`, `~u`, `~m`, `~src` and the boolean operators all work
and the separator can be any character:

```bash
--set mitmcloak_rule="/~src 192\.168\.1\.50/chrome-151-ios"      # the iPhone
--set mitmcloak_rule="/~src 192\.168\.1\.51/chrome-151-android"  # the Android
--set mitmcloak_rule="/~d .*\.example\.com/firefox-148-linux"
--set mitmcloak_bypass="~d internal\.corp"
```

</details>

<details>
<summary><b>Driving it from Python</b></summary>
<br>

One line, and every `httpcloak.Session` keyword is forwarded untouched, so a new httpcloak
release is usable without waiting for a mitmcloak release:

```python
from mitmcloak import Bridge

addons = [Bridge("chrome-151-windows", headers="replace", disable_ech=True)]
```

Full ownership, when you want to build the session yourself:

```python
import httpcloak
from mitmcloak import Bridge

def session_for(flow):
    if flow.request.pretty_host.endswith("example.com"):
        return httpcloak.Session(preset="chrome-151-ios", ja3=my_ja3, proxy="http://...")
    return None          # fall through to normal resolution

addons = [Bridge(session=session_for)]
```

The session is used as given. It is not wrapped, inspected or limited, except for three
flags that are correctness rather than preference: the cookie jar, the conditional cache
and redirect following are all turned off, because the real client owns those.

Custom JSON presets work here for free through `httpcloak.load_preset_from_json`, which is
worth knowing: httpcloak lets you describe a fingerprint down to the TLS extension, and
mitmcloak does nothing to hide that.

</details>

<details>
<summary><b>Commands</b></summary>
<br>

Available in the mitmproxy TUI and mitmweb, with tab completion:

```text
mitmcloak.presets                 every preset, built in and mirrored
mitmcloak.preset <name>           switch the static preset
mitmcloak.preset.load <path>      load a JSON preset file
mitmcloak.preset.describe <name>  fully resolved JSON for a preset
mitmcloak.mirror.list             fingerprints mirrored this session
mitmcloak.mirror.export <dir>     write them out for reuse
mitmcloak.stats                   counters, including what was not bridged
```

Bridged flows carry a `mitmcloak` entry in their metadata (preset, route, upstream
protocol, timing), so `~meta` filters on it and mitmweb shows it.

</details>

<details>
<summary><b>Proxy modes, and which are verified</b></summary>
<br>

| mode | status |
|---|---|
| `regular` (default) | works, with mirroring |
| `socks5` | works, with mirroring |
| `upstream:...` | works; the upstream proxy is handed to httpcloak, see below |
| `reverse:...` | works, but the client speaks plain HTTP to the local port, so there is no ClientHello to mirror and the static preset governs |
| `transparent` | works, with mirroring; verified against an origin that reports the ClientHello it saw |
| `wireguard` | works, with mirroring; same verification, through the tunnel |
| `local` | needs real root and is untested here, see below |

**On transparent and wireguard.** Both were verified in an isolated network namespace
against a local TLS origin that parses the ClientHello it receives and reports its
identity, so the check is that the client's own fingerprint arrives, not merely that a
200 comes back:

```text
                                    origin saw
curl straight to the origin         stable_id=c48b918794d3  30 ciphers
curl through plain mitmproxy        stable_id=da93061cb016  28 ciphers
curl through mitmcloak              stable_id=c48b918794d3  30 ciphers
```

Transparent mode was tested the way it is deployed, as a gateway for a second namespace
with the redirect in `PREROUTING`. That detail matters: a `-t nat -A OUTPUT` redirect on
the same host also catches httpcloak's own upstream dial and loops it back into the
proxy. WireGuard mode was tested with a real kernel `wg0` client completing a handshake
against mitmproxy's server. Both reported `bridged=1 mirrored=1`, so nothing looped.

**On local mode.** It shells out to `sudo -n` to run `mitmproxy-linux-redirector`, which
loads an eBPF program, and root inside a user namespace is not enough because `sudo`
itself rejects the mapped uid. Untested here for that reason. Worth knowing how it fails
if you do not have passwordless sudo, because it fails in the good direction:

```text
[..] Failed to elevate privileges
Error logged during startup, exiting...
```

It exits at startup rather than starting and quietly forwarding traffic unintercepted,
so there is no state where you believe you are bridging and are not.

**On upstream mode.** mitmproxy would normally forward everything to the proxy you named,
but the short circuit means it never gets that far. Left alone, your proxy would be
silently bypassed and requests would leave from the real address while you believed
otherwise. mitmcloak reads `--mode upstream:` and hands that proxy to httpcloak instead.
An explicit `--set mitmcloak_proxy=` wins if you set both.

</details>

<details>
<summary><b>Limitations, and what is not covered</b></summary>
<br>

**Flows mitmproxy does not decrypt are not bridged.** `--ignore-hosts`, TLS passthrough
when a client rejects your CA, and raw CONNECT tunnels reach the origin with the client's
own fingerprint. mitmcloak counts these and logs the host once so the gap is visible rather
than silent. The apps most likely to be excluded are the pinned ones, which are often the
apps you most wanted covered.

The consolation: **fingerprint capture and interception are separable**. An app that
refuses your CA still sends its ClientHello in plaintext first, and mitmcloak keeps it.
Those fingerprints are written out like any other, with the H2 block absent because the
connection never got that far. You can fingerprint what you cannot decrypt.

Worth knowing why an app "stops working", because there are three unrelated causes and
none of them is detection:

- **Certificate pinning.** The app carries its own trust store and refuses any CA it does
  not already know. Logged as `tls alert certificate unknown`.
- **QUIC.** Instagram and Facebook default to HTTP/3 over UDP, and an OS proxy setting
  only redirects TCP, so that traffic never reaches the proxy at all.
- **Apps that ignore the proxy setting.** WhatsApp runs its own transport on port 443
  rather than standard TLS.

**A few clients offer cipher suites httpcloak could not complete.** The offer itself is
always copied exactly, so the fingerprint is unaffected; the question is only what
happens if the origin *selects* one of them, in which case the handshake fails after a
correct hello. Four families are missing, all dropped from the Go stack deliberately:
DHE, CCM, ARIA/Camellia and the CBC-SHA384 variants. Every browser offers none of them,
which is why a mirrored browser cannot hit this. OpenSSL, GnuTLS and JSSE clients offer
between six and thirty-two, always behind the AES-GCM, ChaCha20 and TLS 1.3 suites in
the same hello, so an origin would have to prefer one of them over TLS 1.3 to trip it.
Registration names them when it happens:

```text
WARNING mitmcloak: mc-c14fc534d4ff offers 15 cipher(s) httpcloak cannot complete if the
server selects one: 0x009f 0xccaa 0x00a3 ... They are still offered, so the fingerprint
matches; only an origin that prefers one of them will fail.
```

Nothing is planned here. If a real origin is ever found that selects one, the fix is on
httpcloak's side and this is the message that will point at it.

All three fail at or before the handshake, which is earlier than mitmcloak acts. Plain
mitmproxy behaves identically.

**`serverconnect` and `serverconnected` hooks do not fire** on bridged flows, because there
is no upstream connection to announce. If you have an existing addon stack that depends on
them, that is a real behavioural change.

**WebSockets are passed through**, not bridged, until httpcloak speaks them. Only that
connection's fingerprint is mitmproxy's. The upgrade normally happens after the document
and API requests have already gone through.

**Bodies are buffered**, matching stock mitmproxy, which sets `stream_large_bodies` to
`None` by default. Requests over `mitmcloak_max_body` are handed back unbridged and counted.

**Response trailers reach an HTTP/2 client and not an HTTP/1.1 one.** HTTP/1.1 can carry
a trailer block only on a chunked response, and the body arrives from httpcloak already
decoded, so the response goes out with a `Content-Length`. Handing mitmproxy trailers in
that state raises in its HTTP/1 layer rather than degrading, so they are dropped and
counted as `trailers_dropped_h1`. gRPC is HTTP/2-only, so the case that needs them is the
case that gets them.

**Memory tracks live sessions, not traffic.** An httpcloak session costs roughly 190 kB,
and closing one does **not** return that memory to the operating system. Peak usage
therefore follows the high-water mark of concurrently live sessions, so
`mitmcloak_max_sessions` is a memory ceiling as much as a reuse setting:

```text
peak ~= baseline + 128 kB x distinct hosts (mitmproxy's own cost)
                 + 190 kB x mitmcloak_max_sessions
```

Measured, not estimated. It is bounded: serving more requests does not raise it once the
pool is full. Raise the cap for better reuse on many-origin workloads, lower it if memory
matters more. The idle sweep frees sockets and file descriptors but recovers no memory.

If you see `the session pool has a 0% hit rate` in the log, more origins are in play than
the cap allows and every request is building a fresh upstream session.

**The TCP/IP layer is still the host's.** A mirrored iPhone has a Linux stack underneath
it. `mitmcloak_tcp_*` exposes what httpcloak can set; window scale is a kernel limit.

**Extension permutation is not reproduced.** Real Chrome reorders TLS extensions on every
connection, so its raw JA3 changes while its JA4 does not. A mirrored preset replays one
captured order, so its raw JA3 is stable. JA4 and JA3N are unaffected, since both sort.

**`connection_strategy` is forced to `lazy`.** The default, `eager`, opens the upstream TLS
connection *before* the request hook fires, which leaks a Python ClientHello to the origin
even though the request itself goes out through httpcloak. That is a louder signal than not
bridging at all, so mitmcloak corrects it and says so in the log.

**Alpine and musl will not work.** Go's c-shared archive uses initial-exec TLS, which musl
cannot `dlopen` ([golang/go#54805](https://github.com/golang/go/issues/54805)). Use a glibc
image such as `python:3.12-slim`. mitmcloak raises a clear error at import rather than
letting you find out later.

</details>

---

## Load order

mitmcloak's `request` hook runs in addon registration order, so load it **last** if you have
other scripts that modify requests, otherwise their changes will not be included.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The unit tests need neither the network nor the cgo library: the wire parsing in
`mitmcloak/capture.py` has no httpcloak import and is tested against captured ClientHello
fixtures from Chrome, Firefox and curl.

## Licence

MIT.
