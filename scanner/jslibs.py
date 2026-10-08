"""Detect JavaScript libraries and versions from script URLs and inline banners."""
import re

URL_PATTERNS = [
    ("jquery-ui", r"jquery[.-]ui(?:\.min)?[.-]?v?(\d+\.\d+(?:\.\d+)?)|jqueryui/(\d+\.\d+(?:\.\d+)?)/|jquery-ui@(\d+\.\d+(?:\.\d+)?)"),
    ("jquery", r"jquery[.-]v?(\d+\.\d+(?:\.\d+)?)(?:\.min|\.slim)*\.js|jquery/(\d+\.\d+(?:\.\d+)?)/|jquery@(\d+\.\d+(?:\.\d+)?)"),
    ("bootstrap", r"bootstrap[.-]v?(\d+\.\d+(?:\.\d+)?)|bootstrap/(\d+\.\d+(?:\.\d+)?)/|bootstrap@(\d+\.\d+(?:\.\d+)?)"),
    ("angularjs", r"angular(?:js)?[.-]v?(1\.\d+(?:\.\d+)?)|angular(?:\.js)?/(1\.\d+(?:\.\d+)?)/|angular@(1\.\d+(?:\.\d+)?)"),
    ("lodash", r"lodash[.-]v?(\d+\.\d+(?:\.\d+)?)|lodash(?:\.js)?/(\d+\.\d+(?:\.\d+)?)/|lodash@(\d+\.\d+(?:\.\d+)?)"),
    ("moment", r"moment[.-]v?(\d+\.\d+(?:\.\d+)?)|moment(?:\.js)?/(\d+\.\d+(?:\.\d+)?)/|moment@(\d+\.\d+(?:\.\d+)?)"),
    ("handlebars", r"handlebars[.-]v?(\d+\.\d+(?:\.\d+)?)|handlebars(?:\.js)?/(\d+\.\d+(?:\.\d+)?)/|handlebars@(\d+\.\d+(?:\.\d+)?)"),
    ("underscore", r"underscore[.-]v?(\d+\.\d+(?:\.\d+)?)|underscore(?:\.js)?/(\d+\.\d+(?:\.\d+)?)/|underscore@(\d+\.\d+(?:\.\d+)?)"),
    ("dompurify", r"purify[.-]v?(\d+\.\d+(?:\.\d+)?)|dompurify/(\d+\.\d+(?:\.\d+)?)/|dompurify@(\d+\.\d+(?:\.\d+)?)"),
]

BANNER_PATTERNS = [
    ("jquery-ui", r"jQuery UI - v(\d+\.\d+\.\d+)"),
    ("jquery", r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)"),
    ("bootstrap", r"Bootstrap v(\d+\.\d+\.\d+)"),
    ("angularjs", r"AngularJS v(1\.\d+\.\d+)"),
    ("lodash", r"lodash(?:\.com)? (?:<https?://lodash.com/>)?.{0,40}?(\d+\.\d+\.\d+)"),
    ("moment", r"//! moment\.js\s*\n//! version : (\d+\.\d+\.\d+)"),
    ("handlebars", r"Handlebars\.VERSION = \"(\d+\.\d+\.\d+)\"|handlebars v(\d+\.\d+\.\d+)"),
    ("underscore", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("dompurify", r"DOMPurify (\d+\.\d+\.\d+)"),
]

_URL = [(n, re.compile(p, re.I)) for n, p in URL_PATTERNS]
_BANNER = [(n, re.compile(p)) for n, p in BANNER_PATTERNS]


def _first(m):
    return next(g for g in m.groups() if g)


def detect_from_url(src):
    found = []
    for name, rx in _URL:
        m = rx.search(src)
        if m:
            found.append((name, _first(m)))
            if name == "jquery-ui":
                break  # don't double-count as jquery
    return found


def detect_from_text(text):
    found = []
    for name, rx in _BANNER:
        m = rx.search(text[:5000])
        if m:
            found.append((name, _first(m)))
    return found
