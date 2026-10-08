"""A deliberately misconfigured 'citizen services portal' used as a safe local scan target."""
from flask import Flask, make_response

INSECURE_PAGE = """<!doctype html><html><head><title>Citizen Services Portal (demo)</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js"></script>
<script src="/static/js/lodash-4.17.4.min.js"></script>
</head><body><!-- TODO: remove debug login admin/admin before go-live -->
<h1>Citizen Services Portal</h1><form method="post" action="http://portal.example/login">
<input name="user"><input type="password" name="pw"><button>Login</button></form></body></html>"""

HARDENED_PAGE = """<!doctype html><html><head><title>Citizen Services Portal (hardened)</title>
<script src="/static/app.js"></script></head><body><h1>Hardened portal</h1></body></html>"""


def create_demo_target():
    app = Flask(__name__)

    @app.get("/")
    def insecure():
        r = make_response(INSECURE_PAGE)
        r.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
        r.headers["X-Powered-By"] = "PHP/7.2.24"
        r.headers["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"
        r.headers["Access-Control-Allow-Origin"] = "*"
        r.set_cookie("PHPSESSID", "abc123demo")
        return r

    @app.get("/hardened")
    def hardened():
        r = make_response(HARDENED_PAGE)
        r.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "camera=(), geolocation=()",
        })
        r.set_cookie("session", "xyz", secure=True, httponly=True, samesite="Lax")
        return r

    return app


if __name__ == "__main__":
    create_demo_target().run(port=8081)
