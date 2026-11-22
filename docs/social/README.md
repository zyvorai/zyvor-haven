# Social assets

| File | What it is | Rebuild |
|---|---|---|
| `haven-share-card.html` / `.png` | 1200×630 light card: the README hero and the Open Graph preview | `./docs/social/build-social-card.sh` |
| `haven-share-card-dark.html` / `.png` | 1200×630 dark twin for the README `<picture>` (differs only in palette variables and background) | same script |
| `haven-social-card.html` / `.jpg` | 1600×900 (16:9) card for LinkedIn and X: the identity-plane story in five steps | same script |

Needs Google Chrome and macOS `sips` (already on a Mac); nothing is installed. Override the
browser with `CHROME=/path/to/chrome`. The script takes optional output paths:
`build-social-card.sh [social.jpg] [share.png] [share-dark.png]`.

## Palette

Apple-style blue and white. White to `#f5f5f7` background with a faint blue wash, ink `#1d1d1f`,
secondary `#6e6e73`, hairline `#d2d2d7`, blue `#0071e3` to `#2997ff`. Dark: `#000`/`#0b0b0f`, text
`#f5f5f7`, cards `#1d1d1f`, blue `#0a84ff`. Type: Helvetica Neue and Menlo. The Zyvor Z mark is
drawn inline in blue. Orange (`#ff6a2a`) appears exactly once per image, as a single dot.

## GitHub Social preview

The repository's **Social preview** image (Settings → General → Social preview) cannot be set
through the API. After a rebuild, upload `haven-share-card.png` there by hand.

Every claim on the cards is already sourced in the project README and docs (version from
`charts/haven/Chart.yaml`). Licence wording follows `LICENSE`: Zyvor Production Licence v2.0.
