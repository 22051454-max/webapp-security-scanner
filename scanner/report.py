"""Render scan results as Markdown, HTML or JSON vulnerability assessment reports."""
import json
from datetime import datetime, timezone

from jinja2 import Environment, select_autoescape

from .core import SEVERITY_ORDER

_env = Environment(autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)

MD_TMPL = _env.from_string("""# Web Application Vulnerability Assessment Report

**Generated:** {{ generated }}  
**Targets assessed:** {{ results|length }}  
**Method:** Passive, non-intrusive assessment (HTTP response headers, Content Security Policy, cookies, client-side libraries, page content). No exploitation was attempted.

## Executive summary

| Target | Status | Critical | High | Medium | Low | Info | Risk score |
|---|---|---|---|---|---|---|---|
{% for r in results %}
| {{ r.target }} | {{ r.error or r.status }} | {{ r.counts.critical }} | {{ r.counts.high }} | {{ r.counts.medium }} | {{ r.counts.low }} | {{ r.counts.info }} | {{ r.risk_score }}/100 |
{% endfor %}

Total findings: **{{ total }}** ({{ totals.critical }} critical, {{ totals.high }} high, {{ totals.medium }} medium, {{ totals.low }} low, {{ totals.info }} informational).

{% for r in results %}
---

## {{ r.target }}

{% if r.error %}
Scan could not be completed: {{ r.error }}
{% else %}
Final URL: `{{ r.final_url }}` · HTTP {{ r.status }} · scanned {{ r.scanned_at }}

{% if r.libraries %}
**Client-side libraries detected:** {% for l in r.libraries %}{{ l.library }} {{ l.version }}{% if l.vulnerable %} ⚠️{% endif %}{% if not loop.last %}, {% endif %}{% endfor %}

{% endif %}
{% for f in r.findings %}
### {{ loop.index }}. [{{ f.severity|upper }}] {{ f.title }}

- **Category:** {{ f.category }}
- **Evidence:** {{ f.evidence }}
- **Impact:** {{ f.impact }}
- **Remediation:** {{ f.remediation }}
{% if f.references %}
- **References:** {{ f.references|join(', ') }}
{% endif %}

{% else %}
No issues identified by the automated checks.
{% endfor %}
{% endif %}
{% endfor %}
---

*Automated findings should be validated manually before remediation is prioritised. Assess only systems you are authorised to test.*
""")

HTML_TMPL = _env.from_string("""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Assessment Report</title><style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1d2433}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #dde2ea;padding:6px 8px;font-size:14px;text-align:left}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}
.critical{background:#7b1fa2}.high{background:#c62828}.medium{background:#ef6c00}.low{background:#1565c0}.info{background:#607d8b}
.finding{border:1px solid #dde2ea;border-radius:8px;padding:12px 16px;margin:12px 0}code{background:#f1f3f7;padding:1px 4px;border-radius:4px;word-break:break-all}
.muted{color:#667085}
</style></head><body>
<h1>Web Application Vulnerability Assessment Report</h1>
<p class="muted">Generated {{ generated }} · {{ results|length }} target(s) · passive, non-intrusive checks</p>
<h2>Executive summary</h2>
<table><tr><th>Target</th><th>Status</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Risk</th></tr>
{% for r in results %}<tr><td>{{ r.target }}</td><td>{{ r.error or r.status }}</td><td>{{ r.counts.critical }}</td><td>{{ r.counts.high }}</td><td>{{ r.counts.medium }}</td><td>{{ r.counts.low }}</td><td>{{ r.counts.info }}</td><td>{{ r.risk_score }}/100</td></tr>{% endfor %}
</table>
<p>Total findings: <b>{{ total }}</b></p>
{% for r in results %}<hr><h2>{{ r.target }}</h2>
{% if r.error %}<p>Scan could not be completed: {{ r.error }}</p>{% else %}
<p class="muted">Final URL <code>{{ r.final_url }}</code> · HTTP {{ r.status }} · {{ r.scanned_at }}</p>
{% if r.libraries %}<p><b>Libraries:</b> {% for l in r.libraries %}{{ l.library }} {{ l.version }}{% if l.vulnerable %} ⚠️{% endif %}{% if not loop.last %}, {% endif %}{% endfor %}</p>{% endif %}
{% for f in r.findings %}<div class="finding"><span class="sev {{ f.severity }}">{{ f.severity|upper }}</span> <b>{{ f.title }}</b> <span class="muted">· {{ f.category }}</span>
<p><b>Evidence:</b> <code>{{ f.evidence }}</code></p><p><b>Impact:</b> {{ f.impact }}</p><p><b>Remediation:</b> {{ f.remediation }}</p>
{% if f.references %}<p class="muted">{% for ref in f.references %}<a href="{{ ref }}" rel="noopener noreferrer">{{ ref }}</a> {% endfor %}</p>{% endif %}</div>
{% else %}<p>No issues identified by the automated checks.</p>{% endfor %}{% endif %}{% endfor %}
<p class="muted">Automated findings should be validated manually. Assess only systems you are authorised to test.</p></body></html>""")


def _context(results):
    totals = {k: sum(r.counts[k] for r in results) for k in SEVERITY_ORDER}
    return dict(results=results, totals=totals, total=sum(totals.values()),
                generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def to_markdown(results):
    return MD_TMPL.render(**_context(results))


def to_html(results):
    return HTML_TMPL.render(**_context(results))


def to_json(results):
    return json.dumps([r.to_dict() for r in results], indent=2)
