# mitmcloak

Your browser behind mitmproxy already runs the site's JavaScript and produces genuine
telemetry. That half was never broken. What breaks is that the telemetry then leaves over
a **Python TLS handshake**, and real browser behaviour arriving on a Python ClientHello is
a contradiction anyone can spot.

mitmcloak replaces mitmproxy's upstream leg with [httpcloak](https://github.com/sardanioss/httpcloak),
so the bytes on the wire match the client that actually made the request.

```
                        JA4                                   Akamai HTTP/2
plain mitmproxy   t13d2812h1_a01be8c064b6_0d46a1bf4a7c   (none)
with mitmcloak    t13d3013h2_1d37bd780c83_8537cf56674e   3:100;4:65536;2:0|1048510465|0|m,s,a,p
the real client   t13d3013h2_1d37bd780c83_8537cf56674e   3:100;4:65536;2:0|1048510465|0|m,s,a,p
```

It does not defeat challenges. It stops the proxy corrupting a session that was already
legitimate.

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
| `mitmcloak_max_sessions` | `256` | upstream session pool cap |
| `mitmcloak_max_body` | `50 MB` | larger requests are handed back to mitmproxy |
| `mitmcloak_proxy` | | upstream proxy for the httpcloak leg |
| `mitmcloak_ja3` / `mitmcloak_akamai` | | one-off fingerprint overrides |
| `mitmcloak_tcp_ttl` / `_mss` / `_window_size` | | TCP/IP knobs |

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
