#!/bin/sh
# Re-downloads the latin woff2 subsets served from /assets/fonts and regenerates
# web/assets/fonts.css. Run when a font family or weight set changes.
# Requires curl and python3.
set -eu

cd "$(dirname "$0")/.."

FAMILIES='family=Libre+Caslon+Display&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500'
FONT_CSS="$(mktemp)"
trap 'rm -f "$FONT_CSS"' EXIT

# -f makes an HTTP error page fail the script instead of feeding the parser.
curl -sf --fail -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36" \
    "https://fonts.googleapis.com/css2?${FAMILIES}&display=swap" -o "$FONT_CSS"

python3 - "$FONT_CSS" <<'EOF'
import hashlib, re, sys, urllib.request

css = open(sys.argv[1]).read()
blocks = re.findall(r'/\* ([\w-]+) \*/\s*(@font-face \{[^}]+\})', css)
out = []
# Google serves variable families as one file shared by every weight's
# @font-face block; dedupe on the remote URL so browsers download each
# family once instead of once per weight-specific local filename.
fetched = {}
for subset, block in blocks:
    if subset != 'latin':
        continue
    url = re.search(r'url\((https://[^)]+)\)', block).group(1)
    family = re.search(r"font-family: '([^']+)'", block).group(1).replace(' ', '')
    style = re.search(r'font-style: (\w+)', block).group(1)
    weight = re.search(r'font-weight: (\d+)', block).group(1)
    if url not in fetched:
        # The name takes the first weight seen; one variable file backs every
        # weight of the family, so the filename does not describe its coverage.
        fname = f"{family}-{weight}{'-italic' if style == 'italic' else ''}.woff2"
        urllib.request.urlretrieve(url, f"web/assets/fonts/{fname}")
        # ?v= stamps make the woff2 responses immutable-cacheable; the server
        # keys Cache-Control on the query (see /assets in server/src/app.rs).
        stamp = hashlib.sha256(open(f"web/assets/fonts/{fname}", "rb").read()).hexdigest()[:16]
        fetched[url] = f"/assets/fonts/{fname}?v={stamp}"
    out.append(block.replace(url, fetched[url]))

if len(out) == 0:
    # Never overwrite a good fonts.css from an unparsable response.
    raise SystemExit("no latin @font-face blocks found; not writing fonts.css")

open('web/assets/fonts.css', 'w').write(
    "// Self-hosted Google Fonts (latin subsets), OFL 1.1:\n"
    "// Libre Caslon Display, Plus Jakarta Sans, JetBrains Mono.\n"
    "// Regenerate with scripts/fetch-fonts.sh if weights change.\n"
    + "\n".join(out) + "\n"
)
print(f"{len(out)} faces written")
EOF
