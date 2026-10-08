"""CLI: python -m scanner https://example.com [--batch urls.txt] [--out reports] [--format html,md,json]"""
import argparse
import os
import sys

from .core import scan_url
from .report import to_html, to_json, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(description="Passive web application security scanner")
    ap.add_argument("urls", nargs="*", help="Target URLs")
    ap.add_argument("--batch", help="File with one URL per line")
    ap.add_argument("--out", default="reports", help="Output directory")
    ap.add_argument("--format", default="html,md,json")
    ap.add_argument("--allow-private", action="store_true", help="Allow localhost / private IP targets (lab use)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Exit 1 if findings at/above this severity (CI use)")
    a = ap.parse_args(argv)
    urls = list(a.urls)
    if a.batch:
        with open(a.batch) as fh:
            urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not urls:
        ap.error("give at least one URL or --batch file")
    results = []
    for u in urls:
        print(f"[*] Scanning {u} ...", file=sys.stderr)
        r = scan_url(u, allow_private=a.allow_private)
        print(f"    {r.error or f'{len(r.findings)} findings, risk {r.risk_score}/100'}", file=sys.stderr)
        results.append(r)
    os.makedirs(a.out, exist_ok=True)
    writers = {"html": to_html, "md": to_markdown, "json": to_json}
    for fmt in a.format.split(","):
        path = os.path.join(a.out, f"security_report.{fmt}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(writers[fmt](results))
        print(f"[+] Wrote {path}", file=sys.stderr)
    if a.fail_on:
        order = ["critical", "high", "medium", "low"]
        bad = order[: order.index(a.fail_on) + 1]
        if any(f.severity in bad for r in results for f in r.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
