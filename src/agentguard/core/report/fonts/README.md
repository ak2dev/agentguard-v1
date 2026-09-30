# Report fonts

Embedded (base64) into every HTML report so a single downloaded file renders in
the same typefaces as the Agent Guard website, offline, with a CSP that loads
nothing from anywhere.

| File | Font | Source | License |
|---|---|---|---|
| `inter-latin-wght-normal.woff2` | Inter (variable weight), Latin subset | `@fontsource-variable/inter` 5.3.0 | SIL OFL 1.1 — `Inter-OFL.txt` |
| `jetbrains-mono-latin-wght-normal.woff2` | JetBrains Mono (variable weight), Latin subset | `@fontsource-variable/jetbrains-mono` 5.3.0 | SIL OFL 1.1 — `JetBrainsMono-OFL.txt` |

Characters outside the Latin subset fall back to system fonts. To update, copy
the same files from the pinned packages in `site/node_modules/@fontsource-variable/`.
