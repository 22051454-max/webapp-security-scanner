# Web Application Vulnerability Assessment Report

**Generated:** 2026-10-08 17:16 UTC  
**Targets assessed:** 2  
**Method:** Passive, non-intrusive assessment (HTTP response headers, Content Security Policy, cookies, client-side libraries, page content). No exploitation was attempted.

## Executive summary

| Target | Status | Critical | High | Medium | Low | Info | Risk score |
|---|---|---|---|---|---|---|---|
| https://demo-portal.local/ | 200 | 0 | 6 | 11 | 10 | 4 | 96/100 |
| https://demo-portal.local/hardened | 200 | 0 | 0 | 0 | 0 | 0 | 0/100 |

Total findings: **31** (0 critical, 6 high, 11 medium, 10 low, 4 informational).

---

## https://demo-portal.local/

Final URL: `https://demo-portal.local/` · HTTP 200 · scanned 2026-10-08T17:16:05+00:00

**Client-side libraries detected:** jquery 1.12.4 ⚠️, jquery-ui 1.12.1 ⚠️, bootstrap 3.3.7 ⚠️, moment 2.18.1 ⚠️, lodash 4.17.4 ⚠️
### 1. [HIGH] Vulnerable JavaScript library: jquery 1.12.4

- **Category:** Vulnerable components
- **Evidence:** https://code.jquery.com/jquery-1.12.4.min.js: XSS when passing untrusted HTML to DOM manipulation methods (CVE-2020-11022, CVE-2020-11023)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade jquery to 3.5.0 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2020-11022, https://nvd.nist.gov/vuln/detail/CVE-2020-11023

### 2. [HIGH] Vulnerable JavaScript library: moment 2.18.1

- **Category:** Vulnerable components
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js: Path traversal in locale loading (CVE-2022-24785)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade moment to 2.29.2 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2022-24785

### 3. [HIGH] Vulnerable JavaScript library: moment 2.18.1

- **Category:** Vulnerable components
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js: ReDoS in RFC 2822 date parsing (CVE-2022-31129)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade moment to 2.29.4 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2022-31129

### 4. [HIGH] Vulnerable JavaScript library: lodash 4.17.4

- **Category:** Vulnerable components
- **Evidence:** /static/js/lodash-4.17.4.min.js: Prototype pollution in defaultsDeep (CVE-2019-10744)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade lodash to 4.17.12 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2019-10744

### 5. [HIGH] Vulnerable JavaScript library: lodash 4.17.4

- **Category:** Vulnerable components
- **Evidence:** /static/js/lodash-4.17.4.min.js: Command injection via template() (CVE-2021-23337)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade lodash to 4.17.21 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2021-23337

### 6. [HIGH] Password form submits over HTTP

- **Category:** Transport
- **Evidence:** http://portal.example/login
- **Impact:** Credentials are sent in clear text.
- **Remediation:** Serve the login page and its form action over HTTPS only.

### 7. [MEDIUM] Missing HTTP Strict-Transport-Security

- **Category:** Security headers
- **Evidence:** Header `strict-transport-security` not present
- **Impact:** Browsers may connect over plain HTTP, allowing SSL-stripping and session hijacking on hostile networks.
- **Remediation:** Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.
- **References:** https://owasp.org/www-project-secure-headers/#strict-transport-security

### 8. [MEDIUM] Missing clickjacking protection (X-Frame-Options / frame-ancestors)

- **Category:** Security headers
- **Evidence:** Header `x-frame-options` not present
- **Impact:** Pages can be framed by attacker sites to trick users into clicking hidden buttons (clickjacking).
- **Remediation:** Send `X-Frame-Options: DENY` or CSP `frame-ancestors &#39;none&#39;` (or a list of trusted origins).
- **References:** https://owasp.org/www-community/attacks/Clickjacking

### 9. [MEDIUM] CSP allows &#39;unsafe-inline&#39; scripts

- **Category:** Content Security Policy
- **Evidence:** script-src: &#39;self&#39; &#39;unsafe-inline&#39; &#39;unsafe-eval&#39; https:
- **Impact:** Inline script injection (the most common XSS) is not blocked.
- **Remediation:** Move inline scripts to files or use nonces/hashes, then remove &#39;unsafe-inline&#39;.

### 10. [MEDIUM] CSP allows &#39;unsafe-eval&#39;

- **Category:** Content Security Policy
- **Evidence:** script-src: &#39;self&#39; &#39;unsafe-inline&#39; &#39;unsafe-eval&#39; https:
- **Impact:** eval()-style sinks can execute attacker-controlled strings.
- **Remediation:** Refactor code that uses eval/new Function/string setTimeout and remove &#39;unsafe-eval&#39;.

### 11. [MEDIUM] CSP script sources are overly broad

- **Category:** Content Security Policy
- **Evidence:** script-src includes https:
- **Impact:** Attackers can load scripts from any host matching the wildcard (or data: URIs).
- **Remediation:** List exact trusted origins, or use &#39;strict-dynamic&#39; with nonces.

### 12. [MEDIUM] Cookie `PHPSESSID` missing Secure, HttpOnly, SameSite

- **Category:** Cookies
- **Evidence:** PHPSESSID=abc123demo; Path=/
- **Impact:** Session cookies without HttpOnly can be stolen via XSS; without Secure they leak over HTTP; without SameSite they are sent on cross-site requests (CSRF).
- **Remediation:** Set cookies with `Secure; HttpOnly; SameSite=Lax` (or Strict).

### 13. [MEDIUM] Vulnerable JavaScript library: jquery 1.12.4

- **Category:** Vulnerable components
- **Evidence:** https://code.jquery.com/jquery-1.12.4.min.js: Cross-domain AJAX responses executed as script (XSS) (CVE-2015-9251)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade jquery to 3.0.0 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2015-9251

### 14. [MEDIUM] Vulnerable JavaScript library: jquery 1.12.4

- **Category:** Vulnerable components
- **Evidence:** https://code.jquery.com/jquery-1.12.4.min.js: Prototype pollution in jQuery.extend(true, ...) (CVE-2019-11358)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade jquery to 3.4.0 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2019-11358

### 15. [MEDIUM] Vulnerable JavaScript library: jquery-ui 1.12.1

- **Category:** Vulnerable components
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js: XSS via untrusted option values (altField, *Text options, of) (CVE-2021-41182, CVE-2021-41183, CVE-2021-41184)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade jquery-ui to 1.13.0 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2021-41182, https://nvd.nist.gov/vuln/detail/CVE-2021-41183, https://nvd.nist.gov/vuln/detail/CVE-2021-41184

### 16. [MEDIUM] Vulnerable JavaScript library: bootstrap 3.3.7

- **Category:** Vulnerable components
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js: XSS in collapse/scrollspy/tooltip data attributes (CVE-2018-14040, CVE-2018-14041, CVE-2018-14042)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade bootstrap to 3.4.0 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2018-14040, https://nvd.nist.gov/vuln/detail/CVE-2018-14041, https://nvd.nist.gov/vuln/detail/CVE-2018-14042

### 17. [MEDIUM] Vulnerable JavaScript library: bootstrap 3.3.7

- **Category:** Vulnerable components
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js: XSS in tooltip/popover data-template (CVE-2019-8331)
- **Impact:** Known, publicly documented flaws in this version can be exploited (OWASP A06: Vulnerable and Outdated Components).
- **Remediation:** Upgrade bootstrap to 3.4.1 or later (latest stable recommended) and retest dependent code.
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2019-8331

### 18. [LOW] Missing X-Content-Type-Options

- **Category:** Security headers
- **Evidence:** Header `x-content-type-options` not present
- **Impact:** Browsers may MIME-sniff responses, turning uploaded files into executable scripts.
- **Remediation:** Send `X-Content-Type-Options: nosniff`.

### 19. [LOW] Missing Referrer-Policy

- **Category:** Security headers
- **Evidence:** Header `referrer-policy` not present
- **Impact:** Full URLs (which may contain tokens or IDs) leak to third-party sites through the Referer header.
- **Remediation:** Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.

### 20. [LOW] Technology/version disclosure via `server`

- **Category:** Information disclosure
- **Evidence:** `server: Apache/2.4.29 (Ubuntu)`
- **Impact:** Version strings help attackers pick known exploits for the exact software in use.
- **Remediation:** Remove or genericise the `server` header in the web server / framework configuration.

### 21. [LOW] Technology/version disclosure via `x-powered-by`

- **Category:** Information disclosure
- **Evidence:** `x-powered-by: PHP/7.2.24`
- **Impact:** Version strings help attackers pick known exploits for the exact software in use.
- **Remediation:** Remove or genericise the `x-powered-by` header in the web server / framework configuration.

### 22. [LOW] CSP does not restrict object-src

- **Category:** Content Security Policy
- **Evidence:** `script-src &#39;self&#39; &#39;unsafe-inline&#39; &#39;unsafe-eval&#39; https:`
- **Impact:** Plugin content (&lt;object&gt;/&lt;embed&gt;) can be used to bypass script restrictions.
- **Remediation:** Add `object-src &#39;none&#39;`.

### 23. [LOW] CSP does not restrict base-uri

- **Category:** Content Security Policy
- **Evidence:** `script-src &#39;self&#39; &#39;unsafe-inline&#39; &#39;unsafe-eval&#39; https:`
- **Impact:** An injected &lt;base&gt; tag can redirect relative script URLs to an attacker host.
- **Remediation:** Add `base-uri &#39;none&#39;` or `&#39;self&#39;`.

### 24. [LOW] Third-party script without Subresource Integrity

- **Category:** Supply chain
- **Evidence:** https://code.jquery.com/jquery-1.12.4.min.js
- **Impact:** If the CDN is compromised, modified code runs on your site.
- **Remediation:** Add `integrity` and `crossorigin` attributes to third-party &lt;script&gt; tags.
- **References:** https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity

### 25. [LOW] Third-party script without Subresource Integrity

- **Category:** Supply chain
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js
- **Impact:** If the CDN is compromised, modified code runs on your site.
- **Remediation:** Add `integrity` and `crossorigin` attributes to third-party &lt;script&gt; tags.
- **References:** https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity

### 26. [LOW] Third-party script without Subresource Integrity

- **Category:** Supply chain
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js
- **Impact:** If the CDN is compromised, modified code runs on your site.
- **Remediation:** Add `integrity` and `crossorigin` attributes to third-party &lt;script&gt; tags.
- **References:** https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity

### 27. [LOW] Third-party script without Subresource Integrity

- **Category:** Supply chain
- **Evidence:** https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js
- **Impact:** If the CDN is compromised, modified code runs on your site.
- **Remediation:** Add `integrity` and `crossorigin` attributes to third-party &lt;script&gt; tags.
- **References:** https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity

### 28. [INFO] Missing Permissions-Policy

- **Category:** Security headers
- **Evidence:** Header `permissions-policy` not present
- **Impact:** Embedded third-party content can request powerful browser features (camera, geolocation).
- **Remediation:** Send a `Permissions-Policy` that disables features the site does not use, e.g. `camera=(), geolocation=()`.

### 29. [INFO] CORS allows any origin

- **Category:** CORS
- **Evidence:** `Access-Control-Allow-Origin: *`
- **Impact:** Fine for public static assets, risky on endpoints returning user data.
- **Remediation:** Restrict to an allowlist on any endpoint that returns non-public data.

### 30. [INFO] CSP does not set frame-ancestors

- **Category:** Content Security Policy
- **Evidence:** `script-src &#39;self&#39; &#39;unsafe-inline&#39; &#39;unsafe-eval&#39; https:`
- **Impact:** Framing is controlled only by X-Frame-Options, if present.
- **Remediation:** Add `frame-ancestors &#39;self&#39;` (or &#39;none&#39;).

### 31. [INFO] Sensitive-looking HTML comments

- **Category:** Information disclosure
- **Evidence:** TODO: remove debug login admin/admin before go-live
- **Impact:** Comments can reveal internal paths, credentials or debugging notes.
- **Remediation:** Strip developer comments from production builds.

---

## https://demo-portal.local/hardened

Final URL: `https://demo-portal.local/hardened` · HTTP 200 · scanned 2026-10-08T17:16:05+00:00

No issues identified by the automated checks.
---

*Automated findings should be validated manually before remediation is prioritised. Assess only systems you are authorised to test.*