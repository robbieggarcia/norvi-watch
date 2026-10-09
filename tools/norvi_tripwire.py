#!/usr/bin/env python3
"""Norvi tripwire: a plain check, no Claude, between the Norvi Manager's runs.

    python3 tools/norvi_tripwire.py                    # all checks; from the repo root
    python3 tools/norvi_tripwire.py --only site,backend
    python3 tools/norvi_tripwire.py --only dates
    python3 tools/norvi_tripwire.py --dry-run          # check and print, write and send nothing
    python3 tools/norvi_tripwire.py --selftest
    env: GITHUB_TOKEN, GITHUB_REPOSITORY (set by GitHub Actions), NORVI_ROUTINE_ID and NORVI_ROUTINE_TOKEN (optional)

The checks: heynorvi.com with site_check.py (status, manifest match, prices, TLS, http->https), the
backend's /healthz once app.heynorvi.com is live, and the dates in tools/norvi_dates.json. It compares
a summary with the last one (tripwire/norvi-state.json). Only when something changed, or a failure is
still open 6 hours after the last alarm, it trips:
  - opens (or comments on) a GitHub issue in this repo labeled norvi-tripwire, which the Norvi Manager
    reads and closes;
  - fires the Norvi Manager routine when NORVI_ROUTINE_ID and NORVI_ROUTINE_TOKEN are set.
It never changes the site, the backend or any account. Exit 0 always (a broken check is itself a trip).
"""
import datetime as dt
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "tripwire", "norvi-state.json")
DATES = os.path.join(ROOT, "tools", "norvi_dates.json")
SITE_CHECK = next((p for p in (os.path.join(ROOT, "tools", "site_check.py"),
                               os.path.join(ROOT, ".claude", "skills", "site-watch", "scripts", "site_check.py")) if os.path.exists(p)), "")
PAGES = ["/", "/pricing.html", "/receptionists.html", "/about.html", "/app.html"]
PRICES = ["$29", "$49", "$129", "$249", "$24", "$39", "$105", "$205"]
HEALTH = "https://app.heynorvi.com/healthz"
FIRE_URL = "https://api.anthropic.com/v1/claude_code/routines/{}/fire"
DATE_WARN_DAYS = 30
REMIND_HOURS = 6
KEEP_ALIVE_DAYS = 25  # GitHub turns off schedules in a public repo after 60 days without a commit


def site():
    """The site-watch script's JSON, cut down to what should never change between checks."""
    cmd = [sys.executable, SITE_CHECK, "--base", "https://heynorvi.com", "--pages", *PAGES,
           "--manifest", os.path.join(ROOT, "norvi", "site-manifest.json")]
    for p in PRICES:
        cmd += ["--expect", "/pricing.html=" + p]
    try:
        out = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout)
    except Exception as e:  # the check itself broke: report it, never crash
        return {"verdict": "COULDN'T CHECK: " + type(e).__name__}
    pages = {}
    for p in out.get("pages", []):
        path = p.get("url", "?").replace("https://heynorvi.com", "") or "/"
        pages[path] = {"status": p.get("status", "unreachable" if "unavailable" in p else None),
                       "matches_manifest": p.get("matches_manifest"), "missing_text": sorted(p.get("expected_text_missing") or [])}
    # Slowness comes and goes; it stays out of the verdict so a slow minute doesn't trip.
    real = [a for a in out.get("attention", []) if "slow (" not in a]
    verdict = "COULDN'T CHECK" if str(out.get("verdict", "")).startswith("COULDN'T") else ("ATTENTION" if real else "ALL OK")
    tls = (out.get("tls") or {}).get("days_left")
    return {"verdict": verdict, "attention": sorted(real), "pages": pages,
            "http_to_https": (out.get("http_to_https") or {}).get("ok"),
            "tls_warn": tls is not None and tls <= 21, "tls_days": tls}


def backend():
    req = urllib.request.Request(HEALTH, headers={"User-Agent": "norvi-tripwire/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return "ok" if r.status == 200 else "HTTP {}".format(r.status)
    except urllib.error.HTTPError as e:
        return "HTTP {}".format(e.code)
    except urllib.error.URLError as e:
        # Before step 8 (Render) the name doesn't exist: that is "not live yet", not a failure.
        return "not live yet" if "Name or service not known" in str(e.reason) or "nodename" in str(e.reason) else "down: " + str(e.reason)[:60]
    except Exception as e:
        return "down: " + type(e).__name__


def due_dates(today):
    try:
        items = json.load(open(DATES))
    except Exception:
        return ["dates file unreadable"]
    out = []
    for it in items:
        days = (dt.date.fromisoformat(it["date"]) - today).days
        if days <= DATE_WARN_DAYS:
            out.append("{} on {} ({} days): {}".format(it["what"], it["date"], days, it["fix"]))
    return out


def summary(s, b, d):
    """What a trip compares, only for the checks that ran (None = not checked here). Volatile numbers
    (seconds, exact TLS days) stay out so nothing trips on noise."""
    out = {}
    if s is not None:
        out["site"] = {k: v for k, v in s.items() if k != "tls_days"}
    if b is not None:
        out["backend"] = b
    if d is not None:
        out["dates"] = d
    return out


def failing(summ):
    s = summ.get("site", {})
    pages_bad = any(p.get("status") != 200 or p.get("missing_text") for p in s.get("pages", {}).values())
    return (s.get("verdict") == "COULDN'T CHECK" or pages_bad
            or s.get("http_to_https") is False or bool(s.get("tls_warn")) or str(summ.get("backend", "")).startswith(("down", "HTTP"))
            or bool(summ.get("dates")))


def changes(old, new):
    """Plain lines saying what changed between two summaries."""
    if old is None:
        return []
    lines = []
    os_, ns = old.get("site", {}), new.get("site", {})
    if "site" in new and os_.get("verdict") != ns.get("verdict"):
        lines.append("Site check went from {} to {}.".format(os_.get("verdict"), ns.get("verdict")))
    for path, p in ns.get("pages", {}).items():
        q = os_.get("pages", {}).get(path)
        if q != p:
            lines.append("{}: {} (was {}).".format(path, p, q))
    for a in ns.get("attention", []):
        if a not in os_.get("attention", []):
            lines.append("New: " + a)
    for k in ("http_to_https", "tls_warn"):
        if "site" in new and os_.get(k) != ns.get(k):
            lines.append("{} changed: {} (was {}).".format(k, ns.get(k), os_.get(k)))
    if "backend" in new and old.get("backend") != new["backend"]:
        lines.append("Backend health: {} (was {}).".format(new["backend"], old.get("backend")))
    for d in new.get("dates", []):
        if d not in old.get("dates", []):
            lines.append("Coming due: " + d)
    return lines


def decide(state, new, now):
    """(trip?, reason lines, new state). First run only records a baseline unless something already fails."""
    old = state.get("summary") if state else None
    lines = changes(old, new)
    bad = failing(new)
    last = state.get("last_alarm") if state else None
    stale = bad and (not last or (now - dt.datetime.fromisoformat(last)).total_seconds() > REMIND_HOURS * 3600)
    trip = bool(lines) or (old is None and bad) or (bad and stale and old == new)
    if trip and not lines:
        lines = ["Still failing: " + json.dumps(new)[:400]]
    return trip, lines, {"summary": new, "checked_at": now.isoformat(timespec="seconds"),
                         "last_alarm": now.isoformat(timespec="seconds") if trip else last}


def gh(method, path, body=None):
    token, repo = os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_REPOSITORY", "")
    req = urllib.request.Request("https://api.github.com/repos/{}/{}".format(repo, path), method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                                          "User-Agent": "norvi-tripwire/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def raise_issue(lines, now):
    body = "The Norvi tripwire found this at {} UTC:\n\n{}\n\nThe Norvi Manager handles it in its next run and closes this issue.".format(
        now.strftime("%Y-%m-%d %H:%M"), "\n".join("- " + l for l in lines))
    try:
        open_ = gh("GET", "issues?labels=norvi-tripwire&state=open")
        if open_:
            gh("POST", "issues/{}/comments".format(open_[0]["number"]), {"body": body})
            print("commented on issue", open_[0]["number"])
        else:
            n = gh("POST", "issues", {"title": "Norvi tripwire: " + lines[0][:80], "body": body, "labels": ["norvi-tripwire"]})
            print("opened issue", n.get("number"))
    except Exception as e:
        print("issue not written:", type(e).__name__)


def fire(lines):
    token, routine = os.environ.get("NORVI_ROUTINE_TOKEN", "").strip(), os.environ.get("NORVI_ROUTINE_ID", "").strip()
    if not token or not routine:
        print("Norvi Manager not woken: NORVI_ROUTINE_ID or NORVI_ROUTINE_TOKEN not set (the issue waits for its next run)")
        return
    req = urllib.request.Request(FIRE_URL.format(routine), data=json.dumps({"text": "Norvi tripwire: " + lines[0][:200]}).encode(),
                                 headers={"Authorization": "Bearer " + token, "anthropic-version": "2023-06-01",
                                          "anthropic-beta": "experimental-cc-routine-2026-04-01", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print("Norvi Manager woken ({})".format(r.status))
    except urllib.error.HTTPError as e:
        print("Norvi Manager not woken (HTTP {})".format(e.code))
    except Exception as e:
        print("Norvi Manager not woken ({})".format(type(e).__name__))


def main(dry, parts):
    now = dt.datetime.now(dt.timezone.utc)
    new = summary(site() if "site" in parts else None, backend() if "backend" in parts else None,
                  due_dates(now.date()) if "dates" in parts else None)
    try:
        state = json.load(open(STATE))
    except Exception:
        state = None
    trip, lines, nxt = decide(state, new, now)
    print(json.dumps(new, indent=1))
    print("TRIP" if trip else "no change", *lines, sep="\n")
    if dry:
        return
    if trip:
        raise_issue(lines, now)
        fire(lines)
    # A small commit every few weeks keeps GitHub from turning the schedule off in a quiet public repo.
    alive = (state or {}).get("kept_alive")
    fresh = alive and (now - dt.datetime.fromisoformat(alive)).days < KEEP_ALIVE_DAYS
    nxt["kept_alive"] = alive if fresh else now.isoformat(timespec="seconds")
    if state is None or state.get("summary") != nxt["summary"] or trip or not fresh:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(nxt, open(STATE, "w"), indent=1, sort_keys=True)
        print("state written")


def selftest():
    t = dt.datetime(2026, 10, 9, 12, tzinfo=dt.timezone.utc)
    ok = summary({"verdict": "ALL OK", "attention": [], "pages": {"/": {"status": 200, "matches_manifest": True, "missing_text": []}},
                  "http_to_https": True, "tls_warn": False, "tls_days": 76}, "not live yet", [])
    assert not failing(ok)
    trip, _, st = decide(None, ok, t)                      # first run: baseline only
    assert not trip and st["last_alarm"] is None
    trip, _, _ = decide(st, ok, t + dt.timedelta(hours=1))  # nothing changed
    assert not trip
    bad = json.loads(json.dumps(ok)); bad["site"]["pages"]["/"]["matches_manifest"] = False
    trip, lines, st2 = decide(st, bad, t + dt.timedelta(hours=2))  # a change trips once
    assert trip and "/" in lines[0]
    trip, _, _ = decide(st2, bad, t + dt.timedelta(hours=3))     # same change: quiet
    assert not trip
    down = json.loads(json.dumps(ok)); down["backend"] = "down: timeout"
    trip, _, st3 = decide(st, down, t + dt.timedelta(hours=2))
    assert trip and failing(down)
    assert not decide(st3, down, t + dt.timedelta(hours=4))[0]     # still down, reminded only after 6 h
    assert decide(st3, down, t + dt.timedelta(hours=9))[0]
    if os.path.exists(DATES):
        assert due_dates(dt.date(2027, 9, 1))                      # the domain renewal is inside 30 days then
    dates_only = summary(None, None, [])                           # the private repo checks only dates:
    assert not decide(st, dates_only, t + dt.timedelta(hours=1))[0]  # dropping the site check is not a change
    assert decide({"summary": dates_only}, summary(None, None, ["x on 2027-09-25"]), t)[0]
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        only = next((a.split("=", 1)[1] if "=" in a else sys.argv[sys.argv.index(a) + 1] for a in sys.argv if a.startswith("--only")), "site,backend,dates")
        main("--dry-run" in sys.argv, set(only.split(",")))
