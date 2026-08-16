# sipr brand — "Ferrous"

Industrial slab, oxidized orange. Wears the Rust heritage openly.

## Files
- logo/mark.svg — hex + wave mark (works on light and dark)
- logo/mark-mono.svg — single-color mark for stamps, stickers, favicons
- logo/lockup.svg — mark + wordmark, ink text (light grounds)
- logo/lockup-dark.svg — mark + wordmark, paper text (dark grounds)
- logo/mark-512.png, logo/lockup-1600.png, logo/lockup-dark-1600.png — raster exports

Note: the lockup SVGs embed Alfa Slab One as a data-URI font — fine in browsers, but some pipelines (GitHub README image proxy, Figma import) strip embedded fonts; use the PNGs there, or the mark SVG which is pure paths.
- tokens.css — CSS custom properties + @font-face for the bundled fonts
- fonts/ — WOFF2, all SIL Open Font License

## Color
| Role | Hex |
| --- | --- |
| Rust (primary) | #B7410E |
| Rust bright (on dark) | #E05A1E |
| Ink | #221C18 |
| Paper (ground) | #F3ECDF |
| Paper edge (borders) | #DDD2BD |
| Taupe (secondary text) | #7A6F60 |
| Sage (success) | #5E7A52 |
| Charcoal (dark ground) | #1C1613 |

Terminal mapping: rust -> red/orange (208), sage -> green (65), taupe -> bright black, paper -> bright white.

## Type
- Display: Alfa Slab One 400 — product name and big numbers only, always lowercase "sipr"
- Body/UI: Archivo 400/600/800
- Data & code: IBM Plex Mono 400/500

## Mark usage
- Clear space around the lockup: height of the wave (~1/3 mark height) on all sides.
- Minimum mark size 24px; below that use mark-mono.svg.
- Don't recolor the hex; on dark grounds prefer #E05A1E accents around it.
- Wordmark is always lowercase.

Fonts are redistributed under the SIL OFL 1.1 (Alfa Slab One, Archivo, IBM Plex Mono).
