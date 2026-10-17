# How to capture a HAR file (after clicking "Reject all")

`cookie-consent-liar-detector` is a **post-hoc analyzer**: it cannot click the
banner for you. You do the 60-second capture below, then hand it the HAR file.

## Chrome / Edge (recommended)

1. Open a **new Incognito window** (so no extensions or old cookies interfere).
2. Press `F12` (or `Ctrl+Shift+I` / `Cmd+Option+I`) to open DevTools.
3. Go to the **Network** tab.
4. Tick **Preserve log** and tick **Disable cache**.
5. Click the 🚫 **Clear** button to empty the network log.
6. Navigate to the site. The cookie banner appears.
7. Click **"Reject all"** (or the equivalent — reject everything rejectable).
8. Scroll the page up and down once, wait ~10 seconds (lets delayed tags fire).
9. Right-click anywhere in the request list → **Save all as HAR with content**.
10. Save the file, e.g. `site-reject-all.har`.

## Firefox

1. New Private Window → `F12` → **Network** tab.
2. Click the gear icon → tick **Persist Logs**.
3. Clear with the 🚫 button, load the site, click "Reject all", scroll, wait.
4. Click the gear icon → **Save All As HAR**.

## Safari

1. Enable the Develop menu (Settings → Advanced → Show Develop menu).
2. Develop → Show Web Inspector → **Network** tab.
3. Check **Preserve Log**, clear, load the site, reject all, scroll, wait.
4. Click the **Export** button (HAR).

## Then analyze

```bash
python3 liar_detector.py analyze site-reject-all.har --page-domain example.com
python3 liar_detector.py analyze site-reject-all.har --page-domain example.com --json
```

`--page-domain` is optional but recommended: tracker-looking requests served
from the site's *own* domain are reported separately instead of counting
toward the verdict.

## Tips for an evidence-grade capture

- **Incognito/private window** — avoids contamination from logged-in sessions.
- **Reject, don't just close** — closing the banner without choosing is not a
  rejection; the tool can only judge what happened after your click.
- **One capture per choice** — if you also want to test "Accept all", do a
  separate capture in a fresh private window.
- Keep the `.har` file: it is your evidence (timestamps + full URLs per request).
