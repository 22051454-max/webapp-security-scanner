"""Known-vulnerable JavaScript library versions (curated subset of public advisories)."""

# library -> list of (fixed_in_version, severity, ids, summary)
VULN_DB = {
    "jquery": [
        ("1.9.0", "medium", ["CVE-2012-6708"], "XSS via selector strings starting with non-'<' characters"),
        ("3.0.0", "medium", ["CVE-2015-9251"], "Cross-domain AJAX responses executed as script (XSS)"),
        ("3.4.0", "medium", ["CVE-2019-11358"], "Prototype pollution in jQuery.extend(true, ...)"),
        ("3.5.0", "high", ["CVE-2020-11022", "CVE-2020-11023"], "XSS when passing untrusted HTML to DOM manipulation methods"),
    ],
    "jquery-ui": [
        ("1.13.0", "medium", ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], "XSS via untrusted option values (altField, *Text options, of)"),
    ],
    "bootstrap": [
        ("3.4.0", "medium", ["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"], "XSS in collapse/scrollspy/tooltip data attributes"),
        ("3.4.1", "medium", ["CVE-2019-8331"], "XSS in tooltip/popover data-template"),
    ],
    "angularjs": [
        ("1.8.0", "medium", ["CVE-2020-7676"], "XSS via <option> elements in <select>; AngularJS is end-of-life"),
    ],
    "lodash": [
        ("4.17.12", "high", ["CVE-2019-10744"], "Prototype pollution in defaultsDeep"),
        ("4.17.21", "high", ["CVE-2021-23337"], "Command injection via template()"),
    ],
    "moment": [
        ("2.29.2", "high", ["CVE-2022-24785"], "Path traversal in locale loading"),
        ("2.29.4", "high", ["CVE-2022-31129"], "ReDoS in RFC 2822 date parsing"),
    ],
    "handlebars": [
        ("4.7.7", "critical", ["CVE-2021-23369"], "Remote code execution when compiling untrusted templates"),
    ],
    "underscore": [
        ("1.12.1", "high", ["CVE-2021-23358"], "Arbitrary code injection via template()"),
    ],
    "dompurify": [
        ("2.0.17", "medium", ["CVE-2020-26870"], "Mutation XSS sanitizer bypass"),
    ],
}

# Bootstrap 4.x before 4.3.1 is also affected by CVE-2019-8331
BRANCH_OVERRIDES = {("bootstrap", "4"): [("4.3.1", "medium", ["CVE-2019-8331"], "XSS in tooltip/popover data-template")]}


def parse_version(v):
    out = []
    for part in v.split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out + [0] * (3 - len(out)))


def lookup(library, version):
    rules = BRANCH_OVERRIDES.get((library, version.split(".")[0])) or VULN_DB.get(library, [])
    v = parse_version(version)
    return [r for r in rules if v < parse_version(r[0])]
