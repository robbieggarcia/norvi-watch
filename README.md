# Norvi watch

Checks https://heynorvi.com every 30 minutes with plain Python (no AI, no keys in this repo):
each page answers, matches the files that were deployed (`norvi/site-manifest.json`), shows the
right prices, the certificate is good and http goes to https. Once the app is live it also checks
`https://app.heynorvi.com/healthz`.

It stays quiet unless something changes. Then it opens an issue labeled `norvi-tripwire` and wakes
the agent that looks after Norvi. Last result: `tripwire/norvi-state.json`.

    python3 tools/norvi_tripwire.py --only site,backend --dry-run   # try it, sends nothing
    python3 tools/norvi_tripwire.py --selftest
