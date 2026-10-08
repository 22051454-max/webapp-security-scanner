"""Passive checks: security headers, CSP quality, cookies, vulnerable JS libraries, info disclosure.

Only performs normal GET requests that any browser would make. Scan only systems you are authorised to test.
"""
import ipaddress
import re
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from . import jslibs, vulndb

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
UA = "WebSecScanner/1.0 (+passive security assessment)"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    impact: str
    remediation: str
    references: list = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status: int = 0
    scanned_at: str = ""
    findings: list = field(default_factory=list)
    libraries: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    error: str = ""

    @property
    def counts(self):
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    @property
    def risk_score(self):
        w = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        return min(100, sum(w[f.severity] for f in self.findings))

    def to_dict(self):
        d = asdict(self)
        d["counts"], d["risk_score"] = self.counts, self.risk_score
        return d


class TargetNotAllowed(Exception):
    pass


def ensure_public(url, allow_private=False):
    host = urlparse(url).hostname
    if not host:
        raise TargetNotAllowed("Invalid URL")
    if allow_private:
        return
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise TargetNotAllowed(f"{host} resolves to non-public address {ip}")


# ---------- header checks ----------

HEADER_RULES = [
    ("strict-transport-security", "HDR-HSTS", "Missing HTTP Strict-Transport-Security", "medium",
     "Browsers may connect over plain HTTP, allowing SSL-stripping and session hijacking on hostile networks.",
     "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
     ["https://owasp.org/www-project-secure-headers/#strict-transport-security"]),
    ("x-frame-options", "HDR-XFO", "Missing clickjacking protection (X-Frame-Options / frame-ancestors)", "medium",
     "Pages can be framed by attacker sites to trick users into clicking hidden buttons (clickjacking).",
     "Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'` (or a list of trusted origins).",
     ["https://owasp.org/www-community/attacks/Clickjacking"]),
    ("x-content-type-options", "HDR-XCTO", "Missing X-Content-Type-Options", "low",
     "Browsers may MIME-sniff responses, turning uploaded files into executable scripts.",
     "Send `X-Content-Type-Options: nosniff`.", []),
    ("referrer-policy", "HDR-REF", "Missing Referrer-Policy", "low",
     "Full URLs (which may contain tokens or IDs) leak to third-party sites through the Referer header.",
     "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.", []),
    ("permissions-policy", "HDR-PP", "Missing Permissions-Policy", "info",
     "Embedded third-party content can request powerful browser features (camera, geolocation).",
     "Send a `Permissions-Policy` that disables features the site does not use, e.g. `camera=(), geolocation=()`.", []),
]


def check_headers(url, headers):
    out = []
    is_https = url.startswith("https://")
    csp = headers.get("content-security-policy", "")
    for name, fid, title, sev, impact, fix, refs in HEADER_RULES:
        if name == "strict-transport-security" and not is_https:
            continue
        if name == "x-frame-options" and "frame-ancestors" in csp:
            continue
        if name not in headers:
            out.append(Finding(fid, title, sev, "Security headers", f"Header `{name}` not present", impact, fix, refs))
    hsts = headers.get("strict-transport-security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    if hsts and (not m or int(m.group(1)) < 15552000):
        out.append(Finding("HDR-HSTS-SHORT", "HSTS max-age is too short", "low", "Security headers", f"`{hsts}`",
                           "A short max-age lets the protection lapse between visits.",
                           "Use max-age of at least 15552000 (180 days), ideally 31536000."))
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = headers.get(h, "")
        if v and (re.search(r"\d", v) or h != "server"):
            out.append(Finding("INFO-" + h.upper(), f"Technology/version disclosure via `{h}`", "low", "Information disclosure",
                               f"`{h}: {v}`", "Version strings help attackers pick known exploits for the exact software in use.",
                               f"Remove or genericise the `{h}` header in the web server / framework configuration."))
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        out.append(Finding("CORS-WILDCARD-CREDS", "CORS allows any origin with credentials", "high", "CORS",
                           "`Access-Control-Allow-Origin: *` with `Allow-Credentials: true`",
                           "Any website may read authenticated responses if a browser honours the combination.",
                           "Reflect only an allowlist of trusted origins; never combine `*` with credentials."))
    elif acao == "*":
        out.append(Finding("CORS-WILDCARD", "CORS allows any origin", "info", "CORS", "`Access-Control-Allow-Origin: *`",
                           "Fine for public static assets, risky on endpoints returning user data.",
                           "Restrict to an allowlist on any endpoint that returns non-public data."))
    return out


# ---------- CSP ----------

def parse_csp(value):
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def check_csp(headers):
    value = headers.get("content-security-policy", "")
    ro = headers.get("content-security-policy-report-only", "")
    if not value:
        sev = "high"
        ev = "No `Content-Security-Policy` header" + (" (only Report-Only is set, which does not enforce)" if ro else "")
        return [Finding("CSP-MISSING", "Content Security Policy not enforced", sev, "Content Security Policy", ev,
                        "Without CSP, any XSS bug lets injected scripts run with full access to the page, session and data.",
                        "Deploy an enforcing CSP, starting from: `default-src 'self'; script-src 'self'; object-src 'none'; "
                        "base-uri 'none'; frame-ancestors 'self'; form-action 'self'`. Roll out with Report-Only first.",
                        ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"])]
    d = parse_csp(value)
    out = []
    script = d.get("script-src", d.get("default-src"))
    has_nonce_or_hash = script and any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
    if script is None:
        out.append(Finding("CSP-NO-SCRIPT-SRC", "CSP has no script-src or default-src", "high", "Content Security Policy",
                           f"`{value}`", "Scripts from any origin are allowed, so the CSP gives no XSS protection.",
                           "Add `script-src 'self'` (plus nonces/hashes for any required inline scripts)."))
    else:
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            out.append(Finding("CSP-UNSAFE-INLINE", "CSP allows 'unsafe-inline' scripts", "medium", "Content Security Policy",
                               "script-src: " + " ".join(script), "Inline script injection (the most common XSS) is not blocked.",
                               "Move inline scripts to files or use nonces/hashes, then remove 'unsafe-inline'."))
        if "'unsafe-eval'" in script:
            out.append(Finding("CSP-UNSAFE-EVAL", "CSP allows 'unsafe-eval'", "medium", "Content Security Policy",
                               "script-src: " + " ".join(script), "eval()-style sinks can execute attacker-controlled strings.",
                               "Refactor code that uses eval/new Function/string setTimeout and remove 'unsafe-eval'."))
        wild = [s for s in script if s in ("*", "http:", "https:", "data:") or s.startswith("*.")]
        if wild:
            out.append(Finding("CSP-WILDCARD", "CSP script sources are overly broad", "medium", "Content Security Policy",
                               "script-src includes " + ", ".join(wild),
                               "Attackers can load scripts from any host matching the wildcard (or data: URIs).",
                               "List exact trusted origins, or use 'strict-dynamic' with nonces."))
    if "object-src" not in d and "'none'" not in d.get("default-src", []):
        out.append(Finding("CSP-OBJECT-SRC", "CSP does not restrict object-src", "low", "Content Security Policy", f"`{value}`",
                           "Plugin content (<object>/<embed>) can be used to bypass script restrictions.", "Add `object-src 'none'`."))
    if "base-uri" not in d:
        out.append(Finding("CSP-BASE-URI", "CSP does not restrict base-uri", "low", "Content Security Policy", f"`{value}`",
                           "An injected <base> tag can redirect relative script URLs to an attacker host.", "Add `base-uri 'none'` or `'self'`."))
    if "frame-ancestors" not in d:
        out.append(Finding("CSP-FRAME-ANCESTORS", "CSP does not set frame-ancestors", "info", "Content Security Policy", f"`{value}`",
                           "Framing is controlled only by X-Frame-Options, if present.", "Add `frame-ancestors 'self'` (or 'none')."))
    return out


# ---------- cookies ----------

def check_cookies(url, set_cookie_headers):
    out = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        missing = []
        if url.startswith("https://") and "; secure" not in attrs and not attrs.endswith("secure"):
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            sensitive = bool(re.search(r"sess|auth|token|jwt|sid|login", name, re.I))
            out.append(Finding("COOKIE-FLAGS", f"Cookie `{name}` missing {', '.join(missing)}",
                               "medium" if sensitive else "low", "Cookies", raw[:160],
                               "Session cookies without HttpOnly can be stolen via XSS; without Secure they leak over HTTP; "
                               "without SameSite they are sent on cross-site requests (CSRF).",
                               "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or Strict)."))
    return out


# ---------- page content ----------

def check_content(url, html, fetch_script=None):
    out, libs = [], []
    soup = BeautifulSoup(html or "", "html.parser")
    seen = set()
    for tag in soup.find_all("script"):
        src = tag.get("src")
        detected = []
        if src:
            full = urljoin(url, src)
            detected = jslibs.detect_from_url(full)
            if not detected and fetch_script and urlparse(full).netloc == urlparse(url).netloc:
                body = fetch_script(full)
                detected = jslibs.detect_from_text(body or "")
            if url.startswith("https://") and full.startswith("http://"):
                out.append(Finding("MIXED-SCRIPT", "Script loaded over insecure HTTP (mixed content)", "high", "Transport",
                                   full, "A network attacker can replace the script and take over the page.", "Load all scripts over HTTPS."))
            if urlparse(full).netloc not in ("", urlparse(url).netloc) and not tag.get("integrity"):
                out.append(Finding("SRI-MISSING", "Third-party script without Subresource Integrity", "low", "Supply chain",
                                   full, "If the CDN is compromised, modified code runs on your site.",
                                   "Add `integrity` and `crossorigin` attributes to third-party <script> tags.",
                                   ["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"]))
        else:
            detected = jslibs.detect_from_text(tag.string or "")
        for name, ver in detected:
            if (name, ver) in seen:
                continue
            seen.add((name, ver))
            vulns = vulndb.lookup(name, ver)
            libs.append({"library": name, "version": ver, "source": src or "inline", "vulnerable": bool(vulns)})
            for fixed, sev, ids, summary in vulns:
                out.append(Finding("JSLIB-" + name.upper(), f"Vulnerable JavaScript library: {name} {ver}", sev,
                                   "Vulnerable components", f"{src or 'inline script'}: {summary} ({', '.join(ids)})",
                                   "Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).",
                                   f"Upgrade {name} to {fixed} or later (latest stable recommended) and retest dependent code.",
                                   [f"https://nvd.nist.gov/vuln/detail/{i}" for i in ids]))
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or url)
        if form.find("input", {"type": "password"}) and action.startswith("http://"):
            out.append(Finding("FORM-HTTP-PASSWORD", "Password form submits over HTTP", "high", "Transport", action,
                               "Credentials are sent in clear text.", "Serve the login page and its form action over HTTPS only."))
    comments = re.findall(r"<!--(.*?)-->", html or "", re.S)
    leaky = [c.strip()[:120] for c in comments if re.search(r"todo|password|api[_-]?key|debug|staging|internal", c, re.I)]
    if leaky:
        out.append(Finding("INFO-HTML-COMMENTS", "Sensitive-looking HTML comments", "info", "Information disclosure",
                           " | ".join(leaky[:3]), "Comments can reveal internal paths, credentials or debugging notes.",
                           "Strip developer comments from production builds."))
    return out, libs


def analyze_response(url, final_url, status, headers, set_cookies, html, fetch_script=None, redirected_to_https=None):
    headers = {k.lower(): v for k, v in headers.items()}
    res = ScanResult(target=url, final_url=final_url, status=status,
                     scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), headers=headers)
    findings = []
    if final_url.startswith("http://"):
        findings.append(Finding("TLS-NONE", "Site served over plain HTTP", "high", "Transport", final_url,
                                "All traffic, including credentials and session cookies, can be read or modified in transit.",
                                "Serve the site over HTTPS and redirect all HTTP requests to HTTPS."))
    findings += check_headers(final_url, headers)
    findings += check_csp(headers)
    findings += check_cookies(final_url, set_cookies)
    content_findings, libs = check_content(final_url, html, fetch_script)
    findings += content_findings
    res.findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    res.libraries = libs
    return res


def scan_url(url, allow_private=False, timeout=15):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    try:
        ensure_public(url, allow_private)
    except (TargetNotAllowed, socket.gaierror) as exc:
        return ScanResult(target=url, error=str(exc))
    s = requests.Session()
    s.headers["User-Agent"] = UA

    def fetch_script(src):
        try:
            ensure_public(src, allow_private)
            r = s.get(src, timeout=timeout, stream=True)
            return r.raw.read(512 * 1024, decode_content=True).decode("utf-8", "replace")
        except Exception:
            return ""

    try:
        r = s.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return ScanResult(target=url, error=f"Request failed: {type(exc).__name__}")
    raw_headers = getattr(r.raw, "headers", None)
    set_cookies = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
    return analyze_response(url, r.url, r.status_code, dict(r.headers), set_cookies, r.text[:2_000_000], fetch_script)
