import argparse
import sys
import time
import json
import re
import random
import copy
from typing import Any, Dict, Optional
import hashlib
import base64
import shlex

from curl_cffi import requests
from proxy import Proxy
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.http.responses import build_http_response

import os
import sys
import shutil
import subprocess
import asyncio
from curl_cffi.requests import AsyncSession, Cookies
from curl_cffi.const import CurlHttpVersion
from pathlib import Path

def get_paprika_storage_dir() -> Path:
    """
    Determines and builds the canonical configuration and storage directory
    based on the running Operating System following local specifications.
    """
    home = Path.home()
    
    if sys.platform == "win32":
        # Windows AppData (Roaming) directory
        base_dir = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        # macOS standard Application Support directory
        base_dir = home / "Library" / "Application Support"
    else:
        # Linux/Unix standard XDG Config specification fallback
        base_dir = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        
    storage_path = base_dir / "paprika"
    storage_path.mkdir(parents=True, exist_ok=True)

    try:
        storage_path.chmod(0o700)
    except Exception as e:
        print(f"[!] Warning: Could not set strict directory permissions: {e}", file=sys.stderr)

    return storage_path

def load_configuration() -> Dict[str, Any]:
    """
    Loads JSON engine configurations and profiles dynamically. 
    Bootstraps file structure with reliable initial fallbacks if missing.
    """
    storage_dir = get_paprika_storage_dir()
    config_path = storage_dir / "paprika_config.json"
    
    if not config_path.exists():
        # Fallback dictionary to auto-bootstrap configurations
        default_config = {
            "leaky_headers": ["dnt", "sec-gpc", "upgrade-insecure-requests"],
            "strict_prefixes": ["sec-ch-ua"],
            "browser_profiles": {
                "chrome124": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124", "Google Chrome";v="124"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "firefox135": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5"
                },
                "safari184": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9"
                }
            }
        }
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=4)
            print(f"[+] Instantiated default JSON system configuration profile at: {config_path}")
            return default_config
        except Exception as e:
            print(f"[-] Warning: Failed to cache default configuration template locally: {e}", file=sys.stderr)
            return default_config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as err:
        print(f"[-] Fatal: System broken metadata encountered inside config JSON structure: {err}", file=sys.stderr)
        sys.exit(1)
    
def ensure_ca_certificates() -> tuple[Path, Path, Path]:
    """
    Maintains and provisions Root CA validation profiles without requiring 
    external cryptographic wheels or local compiler stacks.
    """
    storage_dir = get_paprika_storage_dir()
    
    ca_key_path = storage_dir / "ca-key.pem"
    ca_cert_path = storage_dir / "ca-cert.pem"
    
    # Check if files have already been initialized on a previous run
    if ca_key_path.exists() and ca_cert_path.exists():
        print(f"[+] Using existing CA credentials found at: {storage_dir}")
        return ca_key_path, ca_cert_path

    print("[*] Certificates not found. Initiating automated cross-platform provisioning...")
    
    # Look for system OpenSSL binary wrapper path
    if not shutil.which("openssl"):
        print("[-] Critical Error: 'openssl' executable could not be resolved on system PATH.", file=sys.stderr)
        if sys.platform == "win32":
            print("[!] Windows Note: Ensure Git for Windows is installed (provides OpenSSL) or install via terminal: 'winget install OpenSSL.OpenSSL'", file=sys.stderr)
        elif sys.platform == "darwin":
            print("[!] macOS Note: Install OpenSSL using Homebrew ('brew install openssl') or verify Xcode CLI tools.", file=sys.stderr)
        else:
            print("[!] Linux Note: Install packages using your packet manager (e.g., 'sudo apt install openssl').", file=sys.stderr)
        sys.exit(1)
        
    try:
        print("[*] Generating 2048-bit Root CA Private Key...")
        # Step 1: Create local root infrastructure key
        subprocess.run(
            ["openssl", "genrsa", "-out", str(ca_key_path), "2048"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        try:
            ca_key_path.chmod(0o600)
        except Exception as e:
            print(f"[!] Warning: Could not lock down private key permissions: {e}", file=sys.stderr)
        
        print("[*] Generating Self-Signed Root CA Certificate (Valid for 10 Years)...")
        # Step 2: Form self-signed root verification profile.
        # Subject identifiers prevent the terminal from pausing for user input during startup.
        subj_string = "/CN=Paprika Privacy Proxy Root CA/O=Paprika Security/C=US"
        
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-nodes",
                "-key", str(ca_key_path),
                "-sha256", "-days", "3650",
                "-out", str(ca_cert_path),
                "-subj", subj_string
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        print(f"[+] Autopilot credentials generated successfully!")
        print(f"[+] Files locked in storage path: {storage_dir}")
        print(f"[!] User reminder: Import 'ca-cert.pem' into your destination browser settings to eliminate TLS handshake warnings.")
        
    except subprocess.CalledProcessError as err:
        print(f"[-] Subprocess operational breakdown during OpenSSL compilation: {err}", file=sys.stderr)
        sys.exit(1)
        
    return ca_key_path, ca_cert_path

class PaprikaClient:
    """
    PaprikaClient wraps curl_cffi to ensure that TLS fingerprints, 
    HTTP/2 settings, and HTTP headers are perfectly synchronized 
    to mimic legitimate consumer browsers.
    """

    def __init__(self, config: Dict[str, Any], target_browser: str):
        self.profiles = config.get("browser_profiles", {})

        if target_browser not in self.profiles:
            raise ValueError(f"Unsupported browser profile: {target_browser}")
            
        self.target_browser = target_browser
        self.base_headers = self.profiles[target_browser]
        self.base_headers_lower = {k.lower() for k in self.base_headers.keys()}

        self.leaky_headers = {h.lower() for h in config.get("leaky_headers", [])}
        self.strict_prefixes = tuple(p.lower() for p in config.get("strict_prefixes", []))

    async def send(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> requests.Response:

        final_headers = self.base_headers.copy()
        
        # Define headers that must dynamically adapt to the specific asset or API being requested
        CONTEXT_HEADERS = {
            'accept', 
            'accept-encoding', 
            'referer', 
            'cookie', 
            'authorization', 
            'x-requested-with',
            'content-type',
            'content-length',
            'origin'
        }

        if headers:
            for k, v in headers.items():
                k_lower = k.lower()
        
                # 1. Always prioritize contextual request payload headers
                if k_lower in CONTEXT_HEADERS:
                    final_headers[k] = v
                    continue
        
                # 2. Skip headers that are already handled by the static browser profile
                if k_lower in self.base_headers_lower:
                    continue
        
                # 3. Strip out known leaky proxy/tracking headers
                if k_lower in self.leaky_headers:
                    continue
        
                # 4. Enforce strict prefix stripping (like sec-ch-ua metadata)
                if self.strict_prefixes and k_lower.startswith(self.strict_prefixes):
                    continue
        
                # 5. Append any remaining safe headers
                final_headers[k] = v

        session = kwargs.pop('session')
        session.cookies.clear()

        return await session.request(
            method=method,
            url=url,
            headers=final_headers,
            impersonate=self.target_browser,
            http_version=CurlHttpVersion.V2TLS,
            **kwargs
        )

class ProfileRotator:
    """
    Dynamically mutates browser profiles to prevent static fingerprinting.
    Locks hardware combinations to maintain plausibility.
    """
    NVIDIA_GPUS = [
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ]
    
    AMD_GPUS = [
        "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (AMD, AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (AMD, AMD Radeon RX 7900 XTX Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ]

    APPLE_GPUS = ["Apple M1", "Apple M1 Pro", "Apple M1 Max", "Apple M2", "Apple M3"]

    @staticmethod
    def mutate_chrome_version(base_ua: str, base_sec_ch_ua: str) -> tuple[str, str]:
        builds = ["124.0.6367.60", "124.0.6367.91", "124.0.6367.118", "124.0.6367.155"]
        chosen_build = random.choice(builds)
        new_ua = re.sub(r'Chrome/124\.0\.0\.0', f'Chrome/{chosen_build}', base_ua)
        brands = ['"Not-A.Brand";v="99"', '"Chromium";v="124"', '"Google Chrome";v="124"']
        random.shuffle(brands)
        return new_ua, ", ".join(brands)

    @classmethod
    def generate_session_spoof(cls, base_profile_name: str, config_data: dict) -> dict:
        profile = copy.deepcopy(config_data.get("browser_profiles", {}).get(base_profile_name, {}))
        js_spoof = profile.get("js_spoof", {})

        # Plausible Hardware Rotation
        if js_spoof.get("platform") == "Win32":
            js_spoof["webgl_renderer"] = random.choice(cls.NVIDIA_GPUS + cls.AMD_GPUS)
            js_spoof["webgl_vendor"] = "Google Inc. (NVIDIA)" if "NVIDIA" in js_spoof["webgl_renderer"] else "Google Inc. (AMD)"
        elif js_spoof.get("platform") == "MacIntel":
            js_spoof["webgl_renderer"] = random.choice(cls.APPLE_GPUS)
            js_spoof["webgl_vendor"] = "Apple Inc."

        # Minor Version Jitter
        if "chrome" in base_profile_name:
            new_ua, new_sec = cls.mutate_chrome_version(profile["User-Agent"], profile["sec-ch-ua"])
            profile["User-Agent"] = new_ua
            profile["sec-ch-ua"] = new_sec

        # Dynamic Noise Seeds
        js_spoof["audio_noise_seed"] = random.uniform(0.00001, 0.00009)
        js_spoof["canvas_r_shift"] = random.choice([-1, 1])
        js_spoof["canvas_g_shift"] = random.choice([-1, 1])
        js_spoof["canvas_b_shift"] = random.choice([-1, 1])
        js_spoof["canvas_poison_alpha"] = round(random.uniform(0.002, 0.006), 4)

        profile["js_spoof"] = js_spoof
        return profile

class PaprikaProxyPlugin(HttpProxyBasePlugin):
    """
    proxy.py Plugin that intercepts incoming HTTP/HTTPS traffic from the local browser
    and routes it entirely through the PaprikaClient to spoof TLS and Headers.
    """
    TARGET_BROWSER = "chrome124"
    CONFIG_DATA: Dict[str, Any] = {}

    # Upgraded from a single instance to a dynamic pool mapping profiles to clients
    _client_pool: Dict[str, Any] = {}

    _session_spoof_cache: Dict[str, dict] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.session: Optional[AsyncSession] = None

    async def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        # Allow CONNECT method to pass through so proxy.py handles the MITM TLS Decryption
        if request.method == b"CONNECT":
            return request

        if self.session is None:
            self.session = AsyncSession()

        # Extract User-Agent early for dynamic profile alignment
        user_agent_str = ""
        for k, v in request.headers.items():
            if k.lower() == b'user-agent':
                user_agent_str = v[1].decode('utf-8', errors='ignore')
                break

        # Dynamic Profile Selection Logic
        target_profile = self.TARGET_BROWSER  # Use CLI argument as the ultimate fallback
        available_profiles = self.CONFIG_DATA.get("browser_profiles", {})

        if "Firefox" in user_agent_str:
            target_profile = "firefox135" if "firefox135" in available_profiles else target_profile
        elif "Chrome" in user_agent_str or "Chromium" in user_agent_str:
            target_profile = "chrome124" if "chrome124" in available_profiles else target_profile
        elif "Safari" in user_agent_str and "Mac" in user_agent_str and "Chrome" not in user_agent_str:
            target_profile = "safari184" if "safari184" in available_profiles else target_profile

        # Fallback safeguard in case the guessed target profile doesn't exist
        if target_profile not in available_profiles and available_profiles:
            target_profile = list(available_profiles.keys())[0]

        # Initialize or retrieve the matched client from the pool
        if target_profile not in PaprikaProxyPlugin._client_pool:
            PaprikaProxyPlugin._client_pool[target_profile] = PaprikaClient(
                config=self.CONFIG_DATA,
                target_browser=target_profile
            )
                    
        # Bind the dynamically matched instance for this specific request iteration
        paprika = PaprikaProxyPlugin._client_pool[target_profile]

        # Construct target URL
        host = request.host.decode('utf-8') if request.host else ""
        port = request.port if request.port else 80
        path = request.path.decode('utf-8') if request.path else "/"
        
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"

        # Extract client headers (filtering out proxy/hop-by-hop headers)
        client_headers = {}
        for k, v in request.headers.items():
            key_str = k.decode('utf-8')
            if key_str.lower() not in ('host', 'proxy-connection', 'connection'):
                client_headers[key_str] = v[1].decode('utf-8')

        try:
            # Send using curl_cffi to mask TLS/Headers via the dynamically chosen client
            response = await paprika.send(
                method=request.method.decode('utf-8'),
                url=url,
                session=self.session,
                headers=client_headers,
                data=request.body if request.body else None,
                allow_redirects=False
            )
        
            # Reconstruct response headers to send back to the browser
            resp_headers = {}
            csp_headers = []
            
            for k, v in response.headers.items():
                k_lower = k.lower()
                            
                if k_lower in (
                    'content-encoding', 
                    'transfer-encoding', 
                    'content-length'
                ):
                    continue

                if k_lower in ('content-security-policy', 
                               'content-security-policy-report-only', 
                               'x-content-security-policy'
                ):
                    csp_headers.append((k, v))
                    continue
                                
                resp_headers[k.encode('utf-8')] = v.encode('utf-8')
                    
            body = response.content
            content_type = response.headers.get("content-type", "").lower()
        
            # Execute active JavaScript execution ecosystem spoofing if content type is HTML
            if "text/html" in content_type:

                session_key = f"{target_profile}:{host}"

                if session_key not in PaprikaProxyPlugin._session_spoof_cache:
                    dynamic_profile = ProfileRotator.generate_session_spoof(target_profile, self.CONFIG_DATA)
                    PaprikaProxyPlugin._session_spoof_cache[session_key] = dynamic_profile.get("js_spoof", {})

                js_data = PaprikaProxyPlugin._session_spoof_cache[session_key]

                json_payload = json.dumps(js_data).replace("</", "<\\/")
                    
                # High-performance native wrapper designed to preserve prototype .toString() metrics
                js_content_str = """
                (function() {
                    const paprikaStealthCore = function(spoofData) {
                        if (window.__PAPRIKA_SECURED__) return;
                        window.__PAPRIKA_SECURED__ = true;
                            
                        const spoof = spoofData;
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
                                                                    
                        const mockPropertyGetter = (targetObj, propName, mockValue) => {
                            const getterFn = function() { return mockValue; };
                            Object.defineProperty(getterFn, 'name', { value: `get ${propName}`, configurable: true });
                            toStringRegistry.set(getterFn, `function get ${propName}() { [native code] }`);
                                                                                    
                            Object.defineProperty(targetObj, propName, {
                                get: getterFn,
                                configurable: true,
                                enumerable: true 
                            });
                        };
                                                                            
                        if (navigator.webdriver !== undefined) {
                            mockPropertyGetter(Navigator.prototype, 'webdriver', undefined);
                        }
                                                                            
                        if (spoof.platform) mockPropertyGetter(Navigator.prototype, 'platform', spoof.platform);
                        if (spoof.hardwareConcurrency) mockPropertyGetter(Navigator.prototype, 'hardwareConcurrency', spoof.hardwareConcurrency);
                        if (spoof.deviceMemory !== undefined && spoof.deviceMemory !== null) mockPropertyGetter(Navigator.prototype, 'deviceMemory', spoof.deviceMemory);
                                                                
                        // --- 1. SCREEN AND GEOMETRY NORMALIZATION ---
                        if (spoof.hardware_metrics) {
                            const m = spoof.hardware_metrics;
                            mockPropertyGetter(Screen.prototype, 'width', m.screenWidth);
                            mockPropertyGetter(Screen.prototype, 'height', m.screenHeight);
                            mockPropertyGetter(Screen.prototype, 'availWidth', m.availWidth);
                            mockPropertyGetter(Screen.prototype, 'availHeight', m.availHeight);
                            mockPropertyGetter(Screen.prototype, 'colorDepth', m.colorDepth);
                            mockPropertyGetter(Screen.prototype, 'pixelDepth', m.colorDepth);
                            mockPropertyGetter(window, 'devicePixelRatio', m.pixelRatio);
                        }
                                                
                        // --- 2. TIMEZONE AND LOCALE NORMALIZATION ---
                        if (spoof.hardware_metrics) {
                            const m = spoof.hardware_metrics;
                            const originalDateTimeFormat = Intl.DateTimeFormat;
                                                                        
                            hideAndHook(Intl, 'DateTimeFormat', function DateTimeFormat(locales, options) {
                                const targetLocale = locales || m.locale || 'en-US';
                                options = options || {};
                                if (!options.timeZone) {
                                    options.timeZone = m.timezone || 'UTC';
                                }
                                return new originalDateTimeFormat(targetLocale, options);
                            });
                              
                            const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
                            hideAndHook(Date.prototype, 'getTimezoneOffset', function getTimezoneOffset() {
                                return m.timezoneOffset !== undefined ? m.timezoneOffset : originalGetTimezoneOffset.apply(this, arguments);
                            });
                        }
                                                
                        // --- 3. WEBRTC STUN/TURN LOCAL IP MASKING ---
                        if (window.RTCPeerConnection) {
                            const originalCreateOffer = RTCPeerConnection.prototype.createOffer;
                            hideAndHook(RTCPeerConnection.prototype, 'createOffer', function createOffer(options) {
                                return originalCreateOffer.apply(this, arguments).then(offer => {
                                    if (offer && offer.sdp) {
                                        offer.sdp = offer.sdp.replace(/c=IN IP4 \\d+\\.\\d+\\.\\d+\\.\\d+/g, 'c=IN IP4 0.0.0.0');
                                        offer.sdp = offer.sdp.replace(/a=candidate:.*?\\s+\\d+\\.\\d+\\.\\d+\\.\\d+\\s+/g, 'a=candidate:1 1 UDP 2013266431 0.0.0.0 ');
                                    }
                                    return offer;
                                });
                            });
                        }
                                                
                        // --- 4. DYNAMIC AUDIO FINGERPRINT STABILIZATION ---
                        if (window.AudioBuffer) {
                            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
                            hideAndHook(AudioBuffer.prototype, 'getChannelData', function getChannelData(channel) {
                                const data = originalGetChannelData.apply(this, arguments);
                                if (data && data.length) {
                                    for (let i = 0; i < data.length; i += 100) {
                                        data[i] = data[i] + (spoof.audio_noise_seed || 0.0001);
                                    }
                                }
                                return data;
                            });
                        }
                                                
                        // --- 5. WEBGL FINGERPRINTING DECEPTION ---
                        const makeGlHook = (ctxProto) => {
                            if (!ctxProto) return;
                            const originalGetParameter = ctxProto.getParameter;
                            hideAndHook(ctxProto, 'getParameter', function getParameter(parameter) {
                                if (parameter === 37445 && spoof.webgl_vendor) return spoof.webgl_vendor;
                                if (parameter === 37446 && spoof.webgl_renderer) return spoof.webgl_renderer;
                                if (parameter === 7936) return spoof.webgl_vendor || originalGetParameter.apply(this, arguments);
                                if (parameter === 7937) return spoof.webgl_renderer || originalGetParameter.apply(this, arguments);
                                return originalGetParameter.apply(this, arguments);
                            });
                        };
                        makeGlHook(WebGLRenderingContext.prototype);
                        if (window.WebGL2RenderingContext) makeGlHook(WebGL2RenderingContext.prototype);
                                                                
                        // --- 6. DYNAMIC CANVAS FINGERPRINTING NOISE ---
                        const applyCanvasNoise = (canvas) => {
                            const offscreen = document.createElement('canvas');
                            offscreen.width = canvas.width || 1;
                            offscreen.height = canvas.height || 1;
                            const offCtx = offscreen.getContext('2d');
                            offCtx.drawImage(canvas, 0, 0);
                            const alpha = spoof.canvas_poison_alpha || 0.004;
                            offCtx.fillStyle = `rgba(255,255,255,${alpha})`;
                            offCtx.fillRect(0, 0, 1, 1);
                            return offscreen;
                        };
                                                                    
                        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                        hideAndHook(HTMLCanvasElement.prototype, 'toDataURL', function toDataURL(type, encoderOptions) {
                            try {
                                const glCtx = this.getContext('webgl') || this.getContext('webgl2');
                                if (glCtx && glCtx.getContextAttributes().preserveDrawingBuffer === false) {
                                    return originalToDataURL.apply(this, arguments); 
                                }
                                const noisyCanvas = applyCanvasNoise(this);
                                return originalToDataURL.call(noisyCanvas, type, encoderOptions);
                            } catch (e) {
                                return originalToDataURL.apply(this, arguments);
                            }
                        });
                                                                    
                        const originalToBlob = HTMLCanvasElement.prototype.toBlob;
                        hideAndHook(HTMLCanvasElement.prototype, 'toBlob', function toBlob(callback, type, quality) {
                            try {
                                const glCtx = this.getContext('webgl') || this.getContext('webgl2');
                                if (glCtx && glCtx.getContextAttributes().preserveDrawingBuffer === false) {
                                    return originalToBlob.apply(this, arguments); 
                                }
                                const noisyCanvas = applyCanvasNoise(this);
                                return originalToBlob.call(noisyCanvas, callback, type, quality);
                            } catch (e) {
                                return originalToBlob.apply(this, arguments);
                            }
                        });
                                                                    
                        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                        hideAndHook(CanvasRenderingContext2D.prototype, 'getImageData', function getImageData(sx, sy, sw, sh, settings) {
                            const imageData = originalGetImageData.apply(this, arguments);
                            try {
                                if (imageData && imageData.data && imageData.data.length >= 4) {
                                    imageData.data[0] = Math.max(0, Math.min(255, imageData.data[0] + (spoof.canvas_r_shift || 1)));
                                    imageData.data[1] = Math.max(0, Math.min(255, imageData.data[1] + (spoof.canvas_g_shift || 1)));
                                    imageData.data[2] = Math.max(0, Math.min(255, imageData.data[2] + (spoof.canvas_b_shift || 1)));
                                }
                            } catch (e) {}
                            return imageData;
                        });
                                                                
                        if (window.Permissions) {
                            const originalQuery = Permissions.prototype.query;
                            hideAndHook(Permissions.prototype, 'query', function query(descriptor) {
                                return descriptor && descriptor.name === 'notifications'
                                    ? Promise.resolve({ state: Notification.permission, onchange: null })
                                    : originalQuery.apply(this, arguments);
                            });
                        }
                    };
                            
                    // Execute core spoofing logic on the parent window
                    const currentSpoofData = __SPOOF_DATA__;
                    paprikaStealthCore(currentSpoofData);
                            
                    // --- IFRAME BYPASS TRAP ---
                    try {
                        const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
                                                    
                        const contentWindowGetter = function() {
                            const cw = originalContentWindow.call(this);
                            if (cw && !cw.__PAPRIKA_SECURED__) {
                                try {
                                    const script = cw.document.createElement('script');
                                    script.textContent = `(${paprikaStealthCore.toString()})(${JSON.stringify(currentSpoofData)});`;
                                                                
                                    if (cw.document.documentElement) {
                                        cw.document.documentElement.appendChild(script);
                                    } else {
                                        cw.document.appendChild(script);
                                    }
                                    cw.__PAPRIKA_SECURED__ = true;
                                } catch (e) {
                                    // Cross-origin boundaries block this, which is expected and safe to ignore
                                }
                            }
                            return cw;
                        };
                            
                        Object.defineProperty(contentWindowGetter, 'name', { value: 'get contentWindow', configurable: true });
                                                    
                        Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                            get: contentWindowGetter,
                            configurable: true,
                            enumerable: true
                        });
                    } catch (e) {}
                })();
                """.replace("__SPOOF_DATA__", json.dumps(js_data)).encode('utf-8')
            
                digest = hashlib.sha256(js_content_str).digest()
                b64_hash = base64.b64encode(digest).decode('utf-8')
                csp_hash_directive = f"'sha256-{b64_hash}'"
            
                stealth_js_payload = f"<script>{js_content_str.decode('utf-8')}</script>".encode('utf-8')
            
                def patch_csp(csp_string: str) -> str:
                    directives = [d.strip() for d in csp_string.split(';') if d.strip()]
                    for i, directive in enumerate(directives):
                        parts = directive.split()
                        if not parts: continue
                                                    
                        name = parts[0].lower()
                        # Inject hash into script directives so the browser natively allows it
                        if name in ('script-src', 'script-src-elem', 'default-src'):
                            if csp_hash_directive not in parts:
                                directives[i] = directive + f" {csp_hash_directive}"
                                                            
                    return "; ".join(directives)
            
                for csp_key, csp_val in csp_headers:
                    patched_val = patch_csp(csp_val.decode('utf-8', errors='ignore'))
                    resp_headers[csp_key] = patched_val.encode('utf-8')
            
                def meta_csp_replacer(match):
                    meta_tag = match.group(0).decode('utf-8', errors='ignore')
                    content_match = re.search(r'content\s*=\s*(["\'])(.*?)\1', meta_tag, re.IGNORECASE)
                    if content_match:
                        quote = content_match.group(1)
                        original_csp = content_match.group(2)
                        patched_csp = patch_csp(original_csp)
                        new_tag = meta_tag.replace(f"content={quote}{original_csp}{quote}", f"content={quote}{patched_csp}{quote}")
                        return new_tag.encode('utf-8')
                    return match.group(0)
                            
                body = re.sub(
                    rb'<meta\s+[^>]*http-equiv\s*=\s*["\']?content-security-policy["\']?[^>]*>',
                    meta_csp_replacer,
                    body,
                    flags=re.IGNORECASE
                )
            
                injection_points = [
                    rb'<head[^>]*>',       
                    rb'<html[^>]*>',       
                    rb'<!doctype\s+html>'   
                ]
                                
                injected = False
                for pattern in injection_points:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        idx = match.end()
                        body = body[:idx] + stealth_js_payload + body[idx:]
                        injected = True
                        break
                                
                    if not injected:
                        body = stealth_js_payload + body
        
            # Recalculate content length based on decoded and altered payload
            resp_headers[b'Content-Length'] = str(len(body)).encode('utf-8')
        
            # Write the spoofed HTTP response back to the browser
            self.client.queue(
                memoryview(
                    build_http_response(
                        status_code=response.status_code,
                        reason=response.reason.encode('utf-8') if response.reason else b"OK",
                        headers=resp_headers,
                        body=body
                    )
                )
            )

        except Exception as e:
            print(f"[-] Paprika Intercept Error for {url}: {e}", file=sys.stderr)
            self.client.queue(
                memoryview(
                    build_http_response(
                        status_code=502,
                        reason=b"Bad Gateway",
                        body=f"Paprika Proxy Error: {e}".encode('utf-8')
                    )
                )
            )
        
        return None

    def on_client_connection_close(self) -> None:
        """Safely tears down the session when the browser closes the socket."""
        if self.session is not None:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.create_task(self.session.close())
            except RuntimeError:
                pass

def set_system_proxy(enable: bool, port: int = 8899):
    """Automatically configures Windows, macOS, or Linux (GNOME) system proxy settings."""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            if enable:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
            winreg.CloseKey(key)
    
        elif sys.platform == "darwin":
            # Mac settings (assumes Wi-Fi is the primary interface)
            state = "on" if enable else "off"
            for proto in ["web", "secureweb"]:
                if enable:
                    subprocess.run(["networksetup", f"-set{proto}proxy", "Wi-Fi", "127.0.0.1", str(port)], capture_output=True)
                subprocess.run(["networksetup", f"-set{proto}proxystate", "Wi-Fi", state], capture_output=True)
    
        elif sys.platform.startswith("linux"):
            # Linux GNOME settings
            mode = "manual" if enable else "none"
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", f"'{mode}'"], capture_output=True)
            if enable:
                for proto in ["http", "https"]:
                    subprocess.run(["gsettings", "set", f"org.gnome.system.proxy.{proto}", "host", "'127.0.0.1'"], capture_output=True)
                    subprocess.run(["gsettings", "set", f"org.gnome.system.proxy.{proto}", "port", str(port)], capture_output=True)
    except Exception as e:
        print(f"[!] Warning: Could not automatically toggle OS proxy: {e}", file=sys.stderr)

PAPRIKA_LOGO = r"""
  _____                 _ _         
 |  __ \               (_) |        
 | |__) |_ _ _ __  _ __ _| | ____ _ 
 |  ___/ _` | '_ \| '__| | |/ / _` |
 | |  | (_| | |_) | |  | |   < (_| |
 |_|   \__,_| .__/|_|  |_|_|\_\__,_|v1.0.0
            | |                     
            |_|                     
"""

def simulate_boot_sequence():
    """Displays the ASCII art and a simulated startup sequence."""
    print("\033c", end="")
    print("\033[91m" + PAPRIKA_LOGO + "\033[0m")
    print("=" * 45)
    print(" PAPRIKA SPOOF PROXY v1.0.0 ")
    print(" FOR PRIVACY AND SCRAPING ")
    print("=" * 45)
    
    boot_steps = [
        "[*] Have a Kolle-Mate!",
        "\033[92m[+] Paprika is on. You may proceed.\033[0m"
    ]
    
    for step in boot_steps:
        time.sleep(0.35)
        print(step)
        sys.stdout.flush()
    print()

def main(custom_args=None):
    config = load_configuration()
    available_profiles = list(config.get("browser_profiles", {}).keys())

    if not available_profiles:
        print("[-] Fatal Configuration Error: Empty or broken profiles array detected inside configuration system map.", file=sys.stderr)
        sys.exit(1)

    default_profile = "chrome124" if "chrome124" in available_profiles else available_profiles[0]

    parser = argparse.ArgumentParser(description="Paprika - TLS/Header Spoofing Client & Proxy")
    parser.add_argument("--mode", choices=["fetch", "proxy"], default="fetch", 
                        help="Run mode: 'fetch' for single URL, 'proxy' for MITM server")
    
    # Fetch mode arguments
    parser.add_argument("-u", "--url", help="Target URL to fetch (required for fetch mode)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP Method")
    
    # Proxy mode arguments
    parser.add_argument("--port", type=int, default=8899, help="Local Proxy Port (default 8899)")
    parser.add_argument("--ca-key-file", help="Path to CA Private Key (required for HTTPS intercept)")
    parser.add_argument("--ca-cert-file", help="Path to CA Certificate (required for HTTPS intercept)")
    parser.add_argument("--ca-signing-key", help="Path to CA Signing Key (required for HTTPS intercept)")

    parser.add_argument(
        '--browser', 
        choices=available_profiles, 
        default=default_profile, 
        help="Target browser impersonation envelope execution profile configuration."
    )
    
    args = parser.parse_args(custom_args)

    PaprikaProxyPlugin.TARGET_BROWSER = args.browser
    PaprikaProxyPlugin.CONFIG_DATA = config

    print(f"[+] Loaded system configurations context. Active target selection: {args.browser}")
    print(f"[+] Active available spoof profiles: {available_profiles}")

    async def async_fetch_main(config, args):
        print(f"[*] Fetching {args.url} as {args.browser}...")
        paprika = PaprikaClient(config=config, target_browser=args.browser)
        try:
            response = await paprika.send(args.method, args.url)
            print(f"[+] Status: {response.status_code}\n[+] Response:\n{response.text[:1000]}")
        except Exception as e:
            print(f"[-] Request failed: {e}")

    if args.mode == "fetch":
        if not args.url:
            parser.error("--url is required when running in 'fetch' mode.")
        asyncio.run(async_fetch_main(config, args))

    elif args.mode == "proxy":
        simulate_boot_sequence()
        print(f"[*] Starting Paprika Proxy on 127.0.0.1:{args.port}")
        print(f"[*] Impersonating: {args.browser}")
            
        # Inject the desired browser into the Proxy Plugin
        PaprikaProxyPlugin.TARGET_BROWSER = args.browser
    
        # Base proxy.py arguments
        proxy_args = [
            '--port', str(args.port),
            '--plugins', f'{__name__}.PaprikaProxyPlugin',
            '--threadless' 
        ]
    
        # Smart credential assessment: Use custom paths if available, otherwise launch automated engine
        if args.ca_key_file and args.ca_cert_file and args.ca_signing_key:
            key_file = args.ca_key_file
            cert_file = args.ca_cert_file
            signing_file = args.ca_signing_key
            print("[+] Using user-defined custom certificate settings.")
        else:
            print("[*] Missing certificate parameters. Engaging automated zero-dependency manager...")
            ca_key, ca_cert = ensure_ca_certificates()
            key_file = str(ca_key)
            cert_file = str(ca_cert)
            signing_file = str(ca_key)
    
        # Inject final targets into proxy stack configuration
        proxy_args.extend([
            '--ca-key-file', key_file,
            '--ca-cert-file', cert_file,
            '--ca-signing-key-file', signing_file
        ])
        print("[+] HTTPS Man-in-the-Middle Interception is ACTIVE.")
    
        with Proxy(proxy_args):
            try:
                # Enable OS proxy automatically
                set_system_proxy(enable=True, port=args.port)
                print(f"[+] System proxy automatically routed to 127.0.0.1:{args.port}")
                print("[*] Proxy is running. Press Ctrl+C to stop.")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Shutting down Paprika Proxy gracefully.")
            finally:
                # Ensure OS proxy is restored even if the script crashes
                set_system_proxy(enable=False)
                print("[+] System proxy restored to normal.")

def interactive_cli():
    print("Welcome to the Paprika.")
    print("Type 'start --mode proxy' to initiate the proxy, or 'exit' to quit.\n")
    
    while True:
        try:
            raw_input = input("paprika-cli> ")
            if not raw_input.strip():
                continue
            
            parsed_args = shlex.split(raw_input)
            base_command = parsed_args[0].lower()
            
            if base_command == "start":
                # Pass the arguments (excluding the 'start' keyword) to argparse
                main(parsed_args[1:])
                
            elif base_command == "exit":
                print("[*] Tearing down environment. Goodbye.")
                break
            else:
                print(f"[-] Command not recognized: {base_command}")
                
        except ValueError as e:
            print(f"[-] Syntax error in command: {e}")
        except KeyboardInterrupt:
            print("\n[*] Exiting CLI.")
            break

if __name__ == "__main__":
    # If standard terminal arguments are passed (e.g. python paprika.py --mode fetch), run normally
    if len(sys.argv) > 1:
        main()
    # Otherwise, drop into the interactive shlex shell
    else:
        interactive_cli()
