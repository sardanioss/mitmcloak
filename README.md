# mitmcloak

Your browser behind mitmproxy already runs the site's JavaScript and produces genuine
telemetry. That half was never broken. What breaks is that the telemetry then leaves over
a **Python TLS handshake**, and real browser behaviour arriving on a Python ClientHello is
a contradiction anyone can spot.

mitmcloak replaces mitmproxy's upstream leg with [httpcloak](https://github.com/sardanioss/httpcloak),
so the bytes on the wire match the client that actually made the request.

Headless Chromium fetching `https://tls.peet.ws/api/all`, three ways:

```
                    JA4                                     Akamai HTTP/2
Chromium direct     t13d1516h2_8daaf6152771_806a8c22fdea    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
via plain mitmproxy t13d2812h2_a01be8c064b6_0d46a1bf4a7c    1:4096;2:0;4:2147483647;5:131072;8:0;3:100;6:65536|2147418112|0|m,s,p,a
via mitmcloak       t13d1516h2_8daaf6152771_806a8c22fdea    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Same browser, same page, one line of difference in how mitmproxy was started. The
`peetprint` hash matches too. Through Cloudflare's own reflector
(`workers.cloudflare.com/cf.json`) the negotiated cipher and the HTTP/2 priority signal
match the direct browser as well, where plain mitmproxy's do not.

It does not defeat challenges. It stops the proxy corrupting a session that was already
legitimate.

## It is a proxy, so the client can be written in anything

mitmcloak is a mitmproxy addon and mitmproxy is Python, so configuring it is Python — but
[tiers 0 and 1](#configuration) are pure config and most users never write any. What sits
in front of it is unconstrained: anything that can speak through an HTTP proxy gets the
fingerprint, with no library and no code change.

```
Go      http.Transport{Proxy: ...}      Rust  reqwest .proxy()
Java    -Dhttp.proxyHost                Node  HTTPS_PROXY=...
curl / PHP / Ruby / C# / a browser / a phone / an app
```

That is wider than httpcloak's own reach, which is Python, Node, .NET and the C library.
A Go or Rust service gets Chrome's TLS and HTTP/2 fingerprints by setting one
environment variable. Two limits are the proxy's rather than mitmcloak's: a client
speaking QUIC/HTTP3 bypasses an HTTP proxy entirely, and a client that pins certificates
will not trust the CA.

## Install

```bash
pip install mitmcloak
python -m mitmcloak install          # writes ~/.mitmproxy/config.yaml, then gets out of the way
mitmdump                             # plain mitmdump, no -s flag
```

That command runs once and exits. It never sits between you and mitmproxy, so `mitmdump`,
`mitmweb` and the `mitmproxy` TUI keep working exactly as they did, with all their own
flags. `python -m mitmcloak uninstall` puts it back.

Prefer to be explicit? `mitmdump -s "$(python -m mitmcloak path)"`.

## Mirror mode

By default mitmcloak reads the fingerprint of whatever client connected and reproduces it
upstream. Point it at your phone, and the origin sees **your phone**, not a preset someone
guessed.

It reads the client's raw ClientHello from mitmproxy's `tls_clienthello` hook and its HTTP/2
preface from `next_layer`, builds an httpcloak preset on the fly, and serves that same
request through it. One request cycle, no capture phase.

Measured against six clients, each compared direct and through the proxy:

| client | JA4 | JA3N | Akamai H2 |
|---|---|---|---|
| curl (OpenSSL, 30 ciphers, no GREASE) | exact | exact | exact |
| Chrome 151 Windows / iOS / Android | exact | exact | exact |
| Firefox 148 / 133 | exact | exact | exact |

Cost: about 2.6 ms once per *distinct* fingerprint, because preset names are
content-addressed. It does not show up in the latency budget.

### Cataloguing everything that goes past

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

### Keeping a fingerprint without keeping the device

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

## Configuration

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
| `mitmcloak_headers` | `merge` | `merge` keeps the client's values inside the preset's block; `replace` keeps only semantic headers |
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

### Per-flow rules use mitmproxy's own filter language

Not a syntax invented here, so `~d`, `~u`, `~m`, `~src` and the boolean operators all work
and the separator can be any character:

```bash
--set mitmcloak_rule="/~src 192\.168\.1\.50/chrome-151-ios"      # the iPhone
--set mitmcloak_rule="/~src 192\.168\.1\.51/chrome-151-android"  # the Android
--set mitmcloak_rule="/~d .*\.example\.com/firefox-148-linux"
--set mitmcloak_bypass="~d internal\.corp"
```

## Using it from Python

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

## Commands

Available in the mitmproxy TUI and mitmweb, with tab completion:

```
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

## Things worth knowing before you rely on it

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

```
WARNING mitmcloak: mc-c14fc534d4ff offers 15 cipher(s) httpcloak cannot complete if the
server selects one: 0x009f 0xccaa 0x00a3 ... They are still offered, so the fingerprint
matches; only an origin that prefers one of them will fail.
```

Nothing is planned here. If a real origin is ever found that selects one, the fix is on
httpcloak's side and this is the message that will point at it.

**A mirrored Chromium's JA3 is stable per origin, where a real one changes per
connection.** Chromium reorders its TLS extensions on every connection, so its JA3 hash
differs each time while its JA4 stays constant. mitmcloak asks httpcloak to reproduce
that, and httpcloak reseeds the shuffle once per session rather than once per connection,
so a pooled session gives one origin one order. Measured with four connections to the
same reflector: the browser direct produced four JA3 hashes and one JA4, through
mitmcloak one JA3 and the same JA4. `--set mitmcloak_session_scope=connection` restores
the rotation today, at the cost of connection reuse and TLS resumption. Everything JA4,
JA3N and the Akamai HTTP/2 string measure is unaffected either way, since all three
normalise ordering.

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

**Header fidelity is capped at `merge` for now.** httpcloak has an exact-headers mode
that emits an ordered list of pairs verbatim, which is what a mirror wants, but it is only
on the synchronous request path. mitmcloak uses `request_async` exclusively, because a
blocking call would stall mitmproxy's event loop for the whole upstream round trip. Once
`request_async` accepts `exact_headers`, a `headers=exact` mode becomes a small change.

**Memory tracks live sessions, not traffic.** An httpcloak session costs roughly 190 kB,
and closing one does **not** return that memory to the operating system. Peak usage
therefore follows the high-water mark of concurrently live sessions, so
`mitmcloak_max_sessions` is a memory ceiling as much as a reuse setting:

```
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

## Proxy modes

| mode | status |
|---|---|
| `regular` (default) | works, with mirroring |
| `socks5` | works, with mirroring |
| `upstream:...` | works; the upstream proxy is handed to httpcloak, see below |
| `reverse:...` | works, but the client speaks plain HTTP to the local port, so there is no ClientHello to mirror and the static preset governs |
| `transparent`, `wireguard`, `local` | untested |

**On upstream mode.** mitmproxy would normally forward everything to the proxy you named,
but the short circuit means it never gets that far. Left alone, your proxy would be
silently bypassed and requests would leave from the real address while you believed
otherwise. mitmcloak reads `--mode upstream:` and hands that proxy to httpcloak instead.
An explicit `--set mitmcloak_proxy=` wins if you set both.

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
