# cookie-consent-liar-detector

**You clicked "Reject all" on the cookie banner. The site smiled, and then quietly pinged Google Analytics, Facebook, and three ad exchanges anyway.**

"Reject all" buttons are often theater. Consent-management platforms misfire, tags load before your choice is read, and "legitimate interest" gets stretched beyond recognition. Until now, proving it meant eyeballing hundreds of network requests yourself.

This tool does the tedious part: you capture the network traffic *after* clicking reject (60 seconds in DevTools — see [HAR-CAPTURE-HOWTO.md](HAR-CAPTURE-HOWTO.md)), and it matches every request against a bundled list of **248 known tracker domains** (compiled from EasyPrivacy, Disconnect, and WhoTracksMe) and gives you an evidence-grade verdict:

- **LIAR** — known trackers fired after rejection, with per-tracker request counts and sample URLs
- **CLEAN** — no known tracker fired
- **INCONCLUSIVE** — the capture is too small or malformed to judge (it says so instead of guessing)

## Quickstart

```bash
# 30-second demo on the bundled sample HAR (planted tracker hits)
python3 liar_detector.py demo

# Analyze your own capture (see HAR-CAPTURE-HOWTO.md for the 60-second capture steps)
python3 liar_detector.py analyze site-reject-all.har --page-domain example.com
python3 liar_detector.py analyze site-reject-all.har --page-domain example.com --json

# Or hand it a plain JSON list of {"url": ..., "method": ...} records
python3 liar_detector.py analyze requests.json
```

Exit codes: `1` = LIAR, `0` = CLEAN, `2` = INCONCLUSIVE — scriptable in CI or audits.

## Example output

The block below is machine-verified: `build_readme.py` runs `liar_detector.py demo`
fresh and splices its stdout here byte-for-byte, and the test suite re-runs the
demo and diffs it against this block (a stale README fails CI).

<!-- DEMO-OUTPUT-START -->
```
analyzing sample capture: page=example-shop.com, consent=rejected
== cookie-consent-liar-detector ==
requests analyzed : 14
tracker list size : 248 known domains
verdict           : LIAR
reason            : 5 request(s) to 5 known tracker domain(s) fired after consent was rejected

trackers that fired after 'reject all':
  - bat.bing.com (Microsoft): 1 request(s)
      e.g. https://bat.bing.com/bat.js
  - bidswitch.net (BidSwitch): 1 request(s)
      e.g. https://x.bidswitch.net/sync?ssp=example
  - facebook.net (Meta): 1 request(s)
      e.g. https://connect.facebook.net/en_US/fbevents.js
  - google-analytics.com (Google): 1 request(s)
      e.g. https://www.google-analytics.com/g/collect?v=2&tid=G-XXXX
  - taboola.com (Taboola): 1 request(s)
      e.g. https://trc.taboola.com/sg/example-shop/123456/tfa.js
```
<!-- DEMO-OUTPUT-END -->

## How it works

1. **Parse** — reads a HAR file (`log.entries[].request.url`) or a plain JSON
   list of request records. Malformed input yields INCONCLUSIVE, never a guess.
2. **Match** — every request host is normalized (lowercased, port stripped) and
   matched against the bundled tracker list on *label boundaries*: 
   `sub.tracker.com` matches, `nottracker.com` does not.
3. **Verdict** — fewer than 5 captured requests is INCONCLUSIVE (the capture
   looks incomplete); any known-tracker hit is LIAR; otherwise CLEAN.
4. **Report** — human-readable evidence (tracker, owner, request count, sample
   URLs) or `--json` for pipelines. With `--page-domain`, tracker-looking hits
   served from the site's own domain are reported separately, not counted
   toward the verdict.

## What it does NOT do

- It is a **post-hoc analyzer, not an automated browser test** — it cannot
  click the banner for you, drive a browser, or verify what choice you made.
- A **CLEAN verdict means "no *known* tracker fired"**, not "no tracking
  happened". The bundled list is a snapshot (~248 domains); new trackers appear
  constantly, and techniques like CNAME cloaking or server-side forwarding can
  hide tracking from request-URL analysis entirely.
- It does **not** judge whether a request was *legal* — some requests after
  rejection may be strictly-necessary or consent-exempt. The tool reports what
  fired; the legal interpretation is yours (or your lawyer's).
- It does **not** detect fingerprinting that happens without network requests,
  or data already collected before you clicked reject.

## Tracker list sources

Vendored snapshot compiled from public tracker intelligence:

- **EasyPrivacy** (easylist.to) — community tracker blocklist
- **Disconnect Tracking Protection** (disconnect.me)
- **WhoTracksMe / Ghostery Tracker Database** (whotracks.me)

Each entry carries its owner and source(s) — see `trackers.py`. This is a
snapshot, not a live sync.

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
