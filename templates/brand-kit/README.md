# Brand Kit

Reusable zimlama brand kit. Original design — Apache-2.0 licensed.

## What's included

- **Logo** (`logo/`) — SVG variants (isotipo, horizontal, watermark)
- **Tokens** (`tokens.css`, `tokens.scss`, `tokens.ts`) — design tokens
- **Report CSS** (`report.css`) — full stylesheet for markdown → PDF
- **Report Cover** (`report-cover/cover.html`) — cover page template
- **Components** (`components/`) — React/TypeScript components

## Color palette

| Token | Hex | Use |
|-------|-----|-----|
| `--zimlama-negro` | `#0a0a0a` | Background, primary text |
| `--zimlama-rojo` | `#c11b05` | Accent, CTAs, links, brand |
| `--zimlama-blanco` | `#faf8f6` | Foreground text on dark |
| `--zimlama-gris` | `#4a4a4a` | Secondary text |
| `--zimlama-piel` | `#7ab23c` | Invader Zim skin tone (logo) |
| `--zimlama-purple` | `#6b3fa0` | Invader Zim uniform (accent) |
| `--sev-critico` | `#890f0a` | Critical severity |
| `--sev-alto` | `#e55934` | High severity |
| `--sev-medio` | `#fbb03b` | Medium severity |
| `--sev-bajo` | `#3c8dbc` | Low severity |
| `--sev-info` | `#6b7280` | Info |

## Fonts

All from Google Fonts (open-source, SIL OFL):

- **Plus Jakarta Sans** — headings (italic 700)
- **Montserrat** — body (400/600)
- **IBM Plex Mono** — code/monospace (400/600)

Load via Google Fonts CDN or include locally under their respective licenses.

## Logo usage

| Variant | Use |
|---------|-----|
| Isotipo | Favicons, app icons, small spaces |
| Horizontal | Headers, document titles, email signatures |
| Vertical | Stacked layouts, square social media |
| Watermark | PDF corners, very low opacity (5%) |

**Do not** modify the logo SVG (don't change colors, proportions, or add elements).

## Severity badges

```html
<span class="badge badge-critico">CRITICAL</span>
<span class="badge badge-alto">HIGH</span>
<span class="badge badge-medio">MEDIUM</span>
<span class="badge badge-bajo">LOW</span>
<span class="badge badge-info">INFO</span>
```

## AI validation badges

```html
<span class="badge badge-confirmed">CONFIRMED</span>
<span class="badge badge-likely">LIKELY</span>
<span class="badge badge-suspected">SUSPECTED</span>
<span class="badge badge-false-positive">FALSE POSITIVE</span>
```

## License

Apache-2.0. See [logo/LICENSE.txt](logo/LICENSE.txt) for full terms.

The brand kit is original work by zimlama. The color values, font names, and structural patterns are not copyrightable. The logo SVGs are original designs.
