# NarrowCTI brand guidelines

NarrowCTI is the permanent product identity. `2.0` is a version or release
qualifier only; it is not part of the product name and must not appear in asset
filenames. Do not add `™` or `®` marks.

## Approved assets

Canonical, source-controlled assets live under `docs/assets/brand/`. Use the
horizontal or vertical logo variants for the available background, the symbol
for compact surfaces, the README banner for repository presentation, and the
favicon for browser identity.

The legacy `docs/assets/narrowcti-logo.png` and
`docs/assets/narrowcti-banner.png` remain retained for historical and
compatibility consumers. New documentation should use the canonical brand
tree. The CybersysBR authorship logo remains available at
`docs/assets/cybersysbr-logo.png`.

## Canonical asset table

| Role | Dark/light use | Canonical file |
| --- | --- | --- |
| Expanded header | Match the surface background | [`horizontal-dark`](../assets/brand/logo/narrowcti-logo-horizontal-dark.svg) / [`horizontal-light`](../assets/brand/logo/narrowcti-logo-horizontal-light.svg) |
| Compact identity | Dark/light compact surfaces | [`symbol-gradient`](../assets/brand/symbol/narrowcti-symbol-gradient.svg) / [`symbol-black`](../assets/brand/symbol/narrowcti-symbol-black.svg) / [`symbol-white`](../assets/brand/symbol/narrowcti-symbol-white.svg) |
| Vertical lockup | Dark/light editorial surfaces | [`vertical-dark`](../assets/brand/logo/narrowcti-logo-vertical-dark.svg) / [`vertical-light`](../assets/brand/logo/narrowcti-logo-vertical-light.svg) |
| Repository banner | README/repository presentation | [`README banner`](../assets/brand/banners/narrowcti-readme-banner-2172x724.png) |
| Browser identity | Browser and tab identity | [`favicon`](../assets/brand/favicon/narrowcti-favicon.ico) |

Keep clear space around the symbol at approximately 10% of the symbol height.
At 32 px and below, prefer the isolated symbol rather than a full wordmark.
For the future expanded header use the horizontal logo; for compact or
collapsed identity use the isolated symbol; for browser identity use the
favicon; and for dark/light surfaces use the matching approved variant. PR-21
does not define the final browser layout; that belongs to a future UI wave.

## Core palette

| Token | Hex | Use |
| --- | --- | --- |
| Navy | `#102A43` | primary dark surfaces |
| Cyan | `#00A8E8` | links, actions and emphasis |
| Slate | `#1E3A5F` | secondary surfaces |
| Cloud | `#F8FAFC` | light backgrounds and text |
| Muted | `#94A3B8` | secondary text and borders |

The official SVG logo artwork also contains `#081827`, `#1FDCF0` and `#008EE8`.
Those are logo-only rendering tokens and are not additional UI palette tokens.

## Usage

Keep clear space around the mark, preserve the supplied SVG viewBox, and do not
stretch, recolor, crop or redraw official assets. Product documentation and
deployment surfaces should use the permanent `NarrowCTI` name consistently.

Legal, registration and INPI material is maintained outside this repository;
the repository stores only the approved operational product assets.
