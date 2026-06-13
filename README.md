# Paprika
**version:** 1.0.0

Paprika is a specialized, programmatic local Man-in-the-Middle (MITM) proxy engineered to prevent client-side profiling, tracking, and anti-bot fingerprinting. By synchronizing Layer 4 (TCP/TLS) handshakes, Layer 7 (HTTP/2) settings framing, and Client Runtime (JavaScript V8/Gecko/WebKit Engine) configurations, Paprika mitigates advanced device-fingerprinting vectors used by modern anti-bot systems (e.g., Akamai, Cloudflare, PerimeterX).

Unlike standard forward proxies that merely modify the `User-Agent` string, Paprika intercepts, reconstructs, and patches incoming traffic bi-directionally to ensure absolute cryptographic and semantic cohesion.

---

## Architecture Overview

```
[ Client Browser ] 
        │ 
        │ (Unpatched HTTP/HTTPS Traffic)
        ▼
[ Paprika Proxy Server ] ──► (Intercepts HTML & Headers)
        │
        ├──► [ Layer 4/7: curl_cffi ] ──► (Spoofs JA3/JA4 & HTTP/2 Frame Settings)
        │
        └──► [ Runtime: JS Injection ] ──► (Patches Prototype Chain & Evades CSP)
        │ 
        ▼
[ Destination Host ]

```

---

## Features! 

### 1. Cryptographic and Transport Layer Impersonation (JA3/JA4 & HTTP/2)

Standard Python network libraries (like `requests` or `httpx`) rely on native OpenSSL configurations, producing highly distinct TLS ClientHello fingerprints (JA3/JA4 hashes) and rigid HTTP/2 frame parameters (e.g., initial window size, max concurrent streams, header table size).
Paprika forces transport-layer fidelity by wrapping `curl_cffi`, which links against `libcurl-impersonate`. This allows the proxy to alter its TLS extensions, cipher suites, grease values, and ALPN negotiations to seamlessly mimic real web browsers at the byte level.

### 2. Bi-Directional Layer 7 Header Sanitization & Context Preservation

Paprika employs a strict header state engine inside its request lifecycle. When an HTTP client sends a request through the proxy, Paprika maps incoming headers against a pre-compiled JSON profile matrix:

* **Context Preservation:** Volatile semantic headers (`Accept`, `Accept-Language`, `Referer`, `Cookie`, `Authorization`) are dynamically permitted to ensure structural application state remains intact.
* **Leaky Header Stripping:** Cross-origin indicators and telemetry headers (`DNT`, `Sec-GPC`, `Upgrade-Insecure-Requests`) are scrubbed.
* **Prefix Evulsion:** Mismatched client hints (e.g., `Sec-CH-UA` headers that do not match the target spoofed profile) are evulsed to avoid cross-layer validation anomalies.

### 3. Execution Environment Normalization via Prototype Poisoning

To deceive client-side fingerprinting scripts (e.g., FingerprintJS, CreepJS), Paprika injects a highly resilient, isolated JavaScript payload into the top of the DOM. This runtime engine overrides global getters and object prototypes to fake hardware specifications, screen geometry, canvas renderings, and hardware audio pipelines.

### 4. Dynamic Content-Security-Policy (CSP) Bypassing

Injecting third-party JavaScript into strict HTTPS environments typically triggers a CSP violation, halting execution. Paprika circumvents this entirely by intercepting the HTTP response stream, computing the cryptographic SHA-256 hash of the payload on the fly, and dynamically rewriting both the HTTP header directives (`Content-Security-Policy`, `X-Content-Security-Policy`) and in-body `<meta http-equiv="Content-Security-Policy">` elements.

---

## Stand-Out Things in Source Code

### Deep Analysis of the Script Injection & Prototype Trap

The snippet below showcases how Paprika isolates and forces structural compliance within the target window runtime while evading standard string-representation inspection techniques.

```javascript
const toStringRegistry = new Map();
                                        
const originalToString = Function.prototype.toString;
Object.defineProperty(Function.prototype, 'toString', {
    value: function toString() {
        if (toStringRegistry.has(this)) return toStringRegistry.get(this);
        if (this === Function.prototype.toString) return "function toString() { [native code] }";
        return originalToString.apply(this, arguments);
    },
    writable: true,
    enumerable: false,
    configurable: true
});
toStringRegistry.set(Function.prototype.toString, "function toString() { [native code] }");
                                        
const hideAndHook = (targetObj, propName, hookedFn) => {
    const originalFn = targetObj[propName];
    if (!originalFn) return;
                                                    
    Object.defineProperty(hookedFn, 'name', { value: originalFn.name, configurable: true });
    toStringRegistry.set(hookedFn, `function ${originalFn.name}() { [native code] }`);
                                                    
    Object.defineProperty(targetObj, propName, {
        value: hookedFn,
        writable: true,
        enumerable: false,
        configurable: true
    });
};

```

#### Technical Mechanics:

1. **`toString` Registry:** Anti-bot execution scripts often scan for hooked functions by evaluating `Function.prototype.toString.call(targetFunction)`. If the return string lacks the exact spacing or native character block structure (`[native code]`), the environment is flagged as manipulated.
2. **Deterministic Functional Proxying:** The `hideAndHook` internal abstraction binds the native functional names back to the overwritten implementation properties. It registers the target hook within an isolated `Map` lookup table, guaranteeing that any inspection of the prototype tree returns an unmodified string output identical to a pristine native engine instance.

### Dynamic CSP Patching and Payload Interception

This block operates within the response phase of the `proxy.py` runtime architecture, intercepting incoming raw HTML buffers to append execution payloads and rewrite server security assertions.

```python
digest = hashlib.sha256(js_content_str).digest()
b64_hash = base64.b64encode(digest).decode('utf-8')
csp_hash_directive = f"'sha256-{b64_hash}'"

def patch_csp(csp_string: str) -> str:
    directives = [d.strip() for d in csp_string.split(';') if d.strip()]
    for i, directive in enumerate(directives):
        parts = directive.split()
        if not parts: continue
                                    
        name = parts[0].lower()
        if name in ('script-src', 'script-src-elem', 'default-src'):
            if csp_hash_directive not in parts:
                directives[i] = directive + f" {csp_hash_directive}"
                                            
    return "; ".join(directives)

```

#### Technical Mechanics:

1. **Cryptographic Self-Signing:** The engine calculates the SHA-256 integrity digest of the compiled JavaScript payload, formatting it to comply with the W3C Content Security Policy Level 3 specification.
2. **AST-less String Tokenization:** The proxy tokens split header configurations across delimiter sequences (`;`) and appends the explicit hash reference targeting valid script execution scopes (`script-src`, `script-src-elem`, or fallback `default-src`). This forces the browser’s native security layout engine to validate and run the injected hook script without requiring unsafe configurations like `'unsafe-inline'`.

---

## Current Architecture Limitations & Bottlenecks

While advanced, Paprika exhibits concrete performance and runtime limitations under continuous or high-scale utilization:

### 1. Unbounded Memory Expansion via Spoof Cache

The engine utilizes a raw, unbounded global dictionary (`PaprikaProxyPlugin._session_spoof_cache`) to store generated fingerprint variables, mapping them permanently against keys structured as `f"{target_profile}:{host}"`.

* **Impact:** In persistent or wide-scale web scraping operations querying thousands of unique domains, this map scales indefinitely. The lack of an eviction schema (such as a Least Recently Used (LRU) algorithm) ensures a deterministic memory leak over long execution lifecycles.

### 2. High Latency & Regex Fragility over Raw Buffers

The mechanism for identifying payload injection landmarks relies strictly on running standard regular expressions over complete incoming HTML byte blocks:

```python
body = re.sub(rb'<meta\s+[^>]*http-equiv\s*=\s*["\']?content-security-policy["\']?[^>]*>', meta_csp_replacer, body, flags=re.IGNORECASE)

```

* **Impact:** This approach requires loading the complete response payload into system memory simultaneously, breaking the asynchronous chunked streaming capability of the proxy proxy network. For multi-megabyte streams, this causes significant Time-To-First-Byte (TTFB) degradation. Furthermore, highly fragmented HTML, uncommon byte-encodings, or inline comments slicing across structural HTML nodes will cause the regex to fail.

---

## Deployment & Installation Architecture

Paprika is available in both GitHub and Codeberg and as a pip package.

### System Prerequisites

Before initializing Paprika, your host environment must have **OpenSSL** installed and accessible via the system `PATH`. Paprika’s automated zero-dependency certificate manager shells out to the OpenSSL binary to generate the 2048-bit Root CA and self-signed certificates for local HTTPS MITM decryption.

* **Windows:** `winget install OpenSSL.OpenSSL` (or via Git for Windows)
* **macOS:** `brew install openssl`
* **Linux:** `sudo apt install openssl`

### Installation via pip

For production or standard daemonized usage, install the pre-compiled package directly via pip:

```bash
pip install paprika-proxy

```

### Installation

**Via GitHub:**

```bash
git clone https://github.com/yourusername/paprika.git
cd paprika
pip install -r requirements.txt

```

**Via Codeberg:**

```bash
git clone https://codeberg.org/yourusername/paprika.git
cd paprika
pip install -r requirements.txt

```

*(Dependencies primarily include `curl_cffi` for Layer-4 impersonation and `proxy.py` for the localized routing server).*

---

## Usage

Paprika operates under two distinct execution topologies: **Fetch Mode** (a single-shot, headless request execution) and **Proxy Mode** (a persistent, multi-threaded MITM interceptor).

If executed without arguments, Paprika drops into an interactive REPL (Read-Eval-Print Loop) shell (`paprika-cli>`) for session-persistent command execution.

### 1. Fetch Mode (Single-Shot Emulation)

Fetch mode is designed for CI/CD pipelines, quick endpoint validation, or localized scraping where spinning up a full proxy daemon is unnecessary. It routes a single request through the `curl_cffi` engine and prints the raw response.

**Syntax:**

```bash
paprika --mode fetch --url <TARGET_URL> [--method <METHOD>] [--browser <PROFILE>]

```

**Example:** Fetch a highly protected JSON endpoint while strictly impersonating Firefox 135 on Windows:

```bash
paprika --mode fetch -u "https://api.protected-site.com/v1/data" -m GET --browser firefox135

```

### 2. Proxy Mode (MITM Intercept Daemon)

Proxy mode binds a local listener that intercepts all outgoing browser or script traffic. It dynamically rewrites Layer 7 headers, injects the JS prototype hooks into HTML responses, and seamlessly handles TLS decryption/re-encryption.

*Note: Upon boot, Paprika will automatically attempt to rewrite your host OS proxy settings (Windows Registry, macOS `networksetup`, or Linux `gsettings`) to route traffic through itself, restoring them upon a graceful exit.*

**Syntax:**

```bash
paprika --mode proxy [--port <PORT>] [--browser <PROFILE>] [--ca-key-file <PATH> ...]

```

**Example:** Spin up the localized MITM proxy on port `8899`, enforcing the Apple Silicon Safari 18.4 fingerprint constraint matrix:

```bash
paprika --mode proxy --port 8899 --browser safari184

```

### Command Line Arguments
| Argument | Context | Description | Default |
| --- | --- | --- | --- |
| `--mode` | Global | Execution topology: `fetch` or `proxy`. | `fetch` |
| `-u`, `--url` | Fetch | The fully qualified target URI. | *None* |
| `-m`, `--method` | Fetch | The HTTP verb (e.g., `GET`, `POST`, `OPTIONS`). | `GET` |
| `--browser` | Global | The configuration profile matrix to map against (`chrome124`, `firefox135`, `safari184`). | `chrome124` |
| `--port` | Proxy | The local loopback port to bind the MITM listener to. | `8899` |
| `--ca-key-file` | Proxy | Explicit path to a custom Root CA Private Key. | *Auto-Generated* |
| `--ca-cert-file` | Proxy | Explicit path to a custom Root CA Public Certificate. | *Auto-Generated* |

-----

**Author**: nulsie
**License**: GNU GPL v3
