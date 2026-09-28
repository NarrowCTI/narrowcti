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
The Community Web expanded header uses the approved horizontal logo. Use the
isolated symbol only for a compact identity surface, the canonical favicon for
browser identity, and the matching approved variant for dark/light surfaces.
The application uses the build-projected canonical files from
`docs/assets/brand/`; do not copy or edit alternative artwork in runtime code.

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
Community Web uses the canonical palette above: Navy `#102A43` for the shell,
Slate `#1E3A5F` for panels, Cloud `#F8FAFC` for primary text, Muted `#94A3B8`
for secondary text/borders, and Cyan `#00A8E8` for actions and current-page
emphasis. Preserve readable contrast when applying the palette responsively.

## Usage

Keep clear space around the mark, preserve the supplied SVG viewBox, and do not
stretch, recolor, crop or redraw official assets. Product documentation and
deployment surfaces should use the permanent `NarrowCTI` name consistently.

Legal, registration and INPI material is maintained outside this repository;
the repository stores only the approved operational product assets.
