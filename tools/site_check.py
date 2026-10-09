#!/usr/bin/env python3
"""Read-only health check for a small website. Stdlib only.

For each URL: HTTP status, final URL after redirects, response time, bytes, sha256 of the body
(compared with a manifest of expected file hashes when one is given), page <title>, required
text snippets, and common security headers. Once per host: TLS certificate expiry (days left)
and whether plain http:// redirects to https://.

Works through an HTTPS proxy (HTTPS_PROXY / https_proxy) when one is set. Anything that can't be
measured is reported as "unavailable" with the reason; it is never reported as fine.

Usage:
  python3 site_check.py --base https://heynorvi.com --pages / /pricing.html /about.html \
      [--manifest norvi/site-manifest.json] [--expect /pricing.html='$29' --expect /pricing.html='$49'] \
      [--warn-days 21] [--timeout 20]

Exit code 0 when everything measured is fine, 1 when something needs attention, 2 on bad usage.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEC_HEADERS = ["strict-transport-security", "x-content-type-options", "content-security-policy",
               "referrer-policy", "x-frame-options"]


def proxy_for(scheme: str):
    for k in (f"{scheme}_proxy", f"{scheme.upper()}_PROXY"):
        v = os.environ.get(k)
        if v:
            return urllib.parse.urlsplit(v if "://" in v else "http://" + v)
    return None


def no_proxy(host: str) -> bool:
    np = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    return any(host == h.strip() or host.endswith("." + h.strip().lstrip(".")) for h in np.split(",") if h.strip())


def fetch(url: str, timeout: float, ctx: ssl.SSLContext | None):
    """GET with redirects. Returns dict with status, final_url, body bytes, headers, seconds."""
    start = time.monotonic()
    handlers = [urllib.request.HTTPSHandler(context=ctx)] if ctx else []
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "site-watch/1.0 (read-only check)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read()
            return {"status": r.status, "final_url": r.geturl(), "body": body,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "seconds": round(time.monotonic() - start, 2)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "final_url": e.geturl(), "body": e.read() or b"",
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "seconds": round(time.monotonic() - start, 2)}
    except Exception as e:  # network refused, DNS, proxy 403, timeout
        return {"error": f"{type(e).__name__}: {e}"[:300], "seconds": round(time.monotonic() - start, 2)}


def first_hop(url: str, timeout: float):
    """Status and Location of the first response without following redirects."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "site-watch/1.0"}), timeout=timeout) as r:
            return {"status": r.status, "location": r.headers.get("Location")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "location": e.headers.get("Location") if e.headers else None}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:300]}


def cert_days_left(host: str, port: int, timeout: float, ctx: ssl.SSLContext):
    try:
        px = None if no_proxy(host) else proxy_for("https")
        if px:
            conn = http.client.HTTPSConnection(px.hostname, px.port or 3128, timeout=timeout, context=ctx)
            conn.set_tunnel(host, port)
            conn.connect()
            sock = conn.sock
        else:
            raw = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName")
        days = (not_after - dt.datetime.now(dt.timezone.utc)).days
        return {"not_after": not_after.date().isoformat(), "days_left": days, "issuer": issuer}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:300]}


def title_of(body: bytes):
    m = re.search(rb"<title[^>]*>(.*?)</title>", body or b"", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip() if m else None


def manifest_key(path: str):
    p = path.lstrip("/")
    return p or "index.html"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="https://example.com")
    ap.add_argument("--pages", nargs="+", default=["/"])
    ap.add_argument("--manifest", help="JSON {files: {path: {sha256, bytes}}}")
    ap.add_argument("--expect", action="append", default=[], metavar="PATH=TEXT",
                    help="text that must appear on PATH (repeatable)")
    ap.add_argument("--warn-days", type=int, default=21)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--cafile", help="extra CA bundle (tests)")
    a = ap.parse_args(argv)

    base = a.base.rstrip("/")
    host = urllib.parse.urlsplit(base).hostname
    ctx = ssl.create_default_context(cafile=a.cafile) if a.cafile else ssl.create_default_context()
    manifest = {}
    if a.manifest:
        with open(a.manifest, encoding="utf-8") as f:
            manifest = json.load(f).get("files", {})
    expects = {}
    for e in a.expect:
        if "=" not in e:
            ap.error(f"bad --expect {e!r}")
        p, txt = e.split("=", 1)
        expects.setdefault(p, []).append(txt)

    attention, unavailable = [], []
    pages = []
    for path in a.pages:
        url = base + (path if path.startswith("/") else "/" + path)
        r = fetch(url, a.timeout, ctx)
        row = {"url": url, "seconds": r.get("seconds")}
        if "error" in r:
            row["unavailable"] = r["error"]
            unavailable.append(f"{path}: {r['error'][:80]}")
            pages.append(row)
            continue
        body = r["body"]
        row.update({"status": r["status"], "final_url": r["final_url"], "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(), "title": title_of(body),
                    "missing_security_headers": [h for h in SEC_HEADERS if h not in r["headers"]]})
        if r["status"] != 200:
            attention.append(f"{path}: HTTP {r['status']}")
        key = manifest_key(path)
        if manifest:
            exp = manifest.get(key)
            if exp is None:
                row["matches_manifest"] = "not in manifest"
            else:
                row["matches_manifest"] = exp.get("sha256") == row["sha256"]
                if not row["matches_manifest"]:
                    attention.append(f"{path}: differs from manifest ({key})")
        missing = [t for t in expects.get(path, []) if t.encode() not in body]
        if expects.get(path):
            row["expected_text_missing"] = missing
            if missing:
                attention.append(f"{path}: missing {missing}")
        if r["seconds"] and r["seconds"] > 5:
            attention.append(f"{path}: slow ({r['seconds']}s)")
        pages.append(row)

    out = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "base": base, "pages": pages}

    port = urllib.parse.urlsplit(base).port or 443
    if base.startswith("https://") and host:
        hop = (first_hop("http://" + base[len("https://"):] + "/", a.timeout) if port == 443
               else {"skipped": "custom port"})
        if "skipped" in hop:
            out["http_to_https"] = hop
        elif "error" not in hop and hop.get("status") in (403, 407):
            out["http_to_https"] = {"unavailable": f"HTTP {hop['status']} on plain http (blocked here, maybe by a proxy)"}
            unavailable.append("http->https: got 403/407, can't tell")
        elif "error" in hop:
            out["http_to_https"] = {"unavailable": hop["error"]}
            unavailable.append("http->https: " + hop["error"][:80])
        else:
            ok = hop.get("status") in (301, 302, 307, 308) and (hop.get("location") or "").startswith("https://")
            out["http_to_https"] = {**hop, "ok": ok}
            if not ok:
                attention.append(f"http:// does not redirect to https:// (status {hop.get('status')})")
        cert = cert_days_left(host, port, a.timeout, ctx)
        out["tls"] = cert
        if "error" in cert:
            unavailable.append("tls: " + cert["error"][:80])
        elif cert["days_left"] < a.warn_days:
            attention.append(f"TLS certificate expires in {cert['days_left']} days ({cert['not_after']})")

    out["attention"] = attention
    out["unavailable"] = unavailable
    measured = [p for p in pages if "unavailable" not in p]
    if not measured:
        out["verdict"] = "COULDN'T CHECK: no page could be fetched from here (use the WebFetch fallback)"
    else:
        out["verdict"] = ("ATTENTION" if attention else "ALL OK") + (" (some checks unavailable)" if unavailable else "")
    print(json.dumps(out, indent=2))
    return 1 if attention else 0


if __name__ == "__main__":
    sys.exit(main())
