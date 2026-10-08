from scanner import vulndb
from scanner.core import check_csp, check_cookies, scan_url
from scanner.jslibs import detect_from_text, detect_from_url
from web import create_app, scan_demo


def test_version_compare():
    assert vulndb.lookup("jquery", "3.4.1")[0][2] == ["CVE-2020-11022", "CVE-2020-11023"]
    assert vulndb.lookup("jquery", "3.7.1") == []
    assert [r[0] for r in vulndb.lookup("bootstrap", "4.1.0")] == ["4.3.1"]
    assert vulndb.lookup("bootstrap", "5.3.0") == []


def test_detect_libraries():
    assert detect_from_url("https://code.jquery.com/jquery-1.12.4.min.js") == [("jquery", "1.12.4")]
    assert detect_from_url("https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js") == [("jquery-ui", "1.12.1")]
    assert detect_from_url("https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js") == [("lodash", "4.17.15")]
    assert detect_from_text("/*! jQuery v3.3.1 | (c) JS Foundation */") == [("jquery", "3.3.1")]


def test_csp_rules():
    ids = {f.id for f in check_csp({"content-security-policy": "script-src 'self' 'unsafe-inline' https:"})}
    assert {"CSP-UNSAFE-INLINE", "CSP-WILDCARD", "CSP-OBJECT-SRC", "CSP-BASE-URI"} <= ids
    assert check_csp({})[0].id == "CSP-MISSING"
    nonce = check_csp({"content-security-policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"})
    assert nonce == []


def test_cookie_flags():
    f = check_cookies("https://x", ["sessionid=1; Path=/"])
    assert f and f[0].severity == "medium" and "HttpOnly" in f[0].title
    assert check_cookies("https://x", ["sessionid=1; Secure; HttpOnly; SameSite=Lax"]) == []


def test_demo_insecure_vs_hardened():
    bad, good = scan_demo("/"), scan_demo("/hardened")
    ids = {f.id for f in bad.findings}
    assert {"JSLIB-JQUERY", "JSLIB-BOOTSTRAP", "JSLIB-MOMENT", "HDR-HSTS", "COOKIE-FLAGS", "INFO-X-POWERED-BY",
            "FORM-HTTP-PASSWORD", "CSP-UNSAFE-INLINE"} <= ids
    assert bad.risk_score > 50
    assert good.findings == []


def test_ssrf_guard_blocks_localhost():
    assert "non-public" in scan_url("http://127.0.0.1:9/").error


def test_web_demo_and_reports():
    c = create_app().test_client()
    r = c.post("/", data={"demo": "1"})
    assert b"Vulnerable JavaScript library" in r.data
    assert b"Executive summary" in c.get("/report.html").data
    assert c.get("/report.json").get_json()[0]["risk_score"] > 0


def test_web_requires_authorisation_ack():
    r = create_app().test_client().post("/", data={"urls": "https://example.com"})
    assert b"authorised" in r.data
