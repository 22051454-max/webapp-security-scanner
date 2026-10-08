import os

from flask import Flask, Response, render_template, request

from demo_target import create_demo_target
from scanner.core import analyze_response, scan_url
from scanner.report import to_html, to_json, to_markdown

MAX_TARGETS = 12


def scan_demo(path):
    """Scan the bundled vulnerable demo site in-process (no network needed)."""
    client = create_demo_target().test_client()
    r = client.get(path)
    url = "https://demo-portal.local" + path
    return analyze_response(url, url, r.status_code, dict(r.headers), r.headers.getlist("Set-Cookie"), r.get_data(as_text=True))


def create_app():
    app = Flask(__name__)
    allow_private = os.environ.get("ALLOW_PRIVATE_TARGETS") == "1"
    last = {}

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route("/", methods=["GET", "POST"])
    def index():
        results, error = None, None
        if request.method == "POST":
            if request.form.get("demo"):
                results = [scan_demo("/"), scan_demo("/hardened")]
            else:
                urls = [u.strip() for u in request.form.get("urls", "").splitlines() if u.strip()][:MAX_TARGETS]
                if not request.form.get("authorized"):
                    error = "Please confirm you are authorised to assess these targets."
                elif not urls:
                    error = "Enter at least one URL."
                else:
                    results = [scan_url(u, allow_private=allow_private) for u in urls]
            if results:
                last["results"] = results
        return render_template("index.html", results=results, error=error, max_targets=MAX_TARGETS)

    @app.get("/report.<fmt>")
    def report(fmt):
        results = last.get("results") or [scan_demo("/")]
        if fmt == "html":
            return Response(to_html(results), mimetype="text/html")
        if fmt == "md":
            return Response(to_markdown(results), mimetype="text/markdown",
                            headers={"Content-Disposition": "attachment; filename=security_report.md"})
        if fmt == "json":
            return Response(to_json(results), mimetype="application/json")
        return "unknown format", 404

    return app
