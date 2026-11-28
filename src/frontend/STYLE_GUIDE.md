# Frontend Styling Guide

This guide defines the styling conventions for `src/frontend/` so human contributors and AI coding tools keep styles consistent, theme-safe, and easy to maintain.

## 1. Design Tokens (Source of Truth)

All CSS custom properties live in:
- `src/styles/tokens.css` (palette, light theme defaults, spacing, radii, typography)
- `src/styles/themes.css` (`[data-theme='dark']` and `[data-theme='light']` overrides)

**Hard rule:** Never invent unverified `--*` variable names (such as `--text-body`, `--accent`, or `--status-warn-bg`). This is enforced by `tests/designSystem.test.mjs`.

Core tokens to use:
- **Surfaces:** `--canvas`, `--surface`, `--surface-muted`, `--surface-hover`, `--bg-input`, `--sidebar`, `--sidebar-hover`, `--sidebar-active`
- **Text:** `--text-heading`, `--text-main`, `--text-muted`, `--color-on-primary`
- **Borders:** `--line`, `--line-divider`, `--line-strong`
- **Brand & Interactive:** `--color-primary`, `--color-primary-hover`, `--color-primary-subtle`, `--color-accent`, `--focus-ring`
- **Status & Semantic Badges/Rows:** `--warning`, `--danger`, `--success`, `--fw-allow`, `--fw-allow-soft`, `--fw-warn`, `--fw-warn-soft`, `--fw-deny`, `--fw-deny-soft`, `--fw-info`, `--fw-info-soft`, `--fw-purple`, `--fw-purple-soft`, `--fw-row-*-bg`, `--fw-row-*-text`
- **Spacing, Radii & Typography:** `--space-1`..`--space-8`, `--control-height`, `--control-height-compact`, `--radius-sm`, `--radius-md`, `--radius-lg`, `--font-ui`, `--font-display`, `--font-mono`, `--font-size-small`, `--font-size-body`, `--font-size-title`
- **Shadows:** `--shadow-panel`, `--shadow-popover`

## 2. Reuse Shared Primitives First

Before adding custom CSS classes, check and reuse:
- Components in `src/components/common/`: `Button`, `ErrorBanner`, `LoadingState`, `Badge`, `AlertBox`, `CollapsibleSection`, `KeyValueGrid`
- Global utility classes in `src/styles/primitives.css`: `.panel`, `.field`, `.action-row`, `.primary-button`, `.secondary-button`, `.outline-button`, `.text-button`, `.button-compact`, `.ui-alert*`, `.ui-collapsible*`, `.ui-kv-*`

## 3. Stylesheet Placement (Stop Growing `App.css`)

- **Do not append new feature styles to `src/App.css`.** `tests/designSystem.test.mjs` enforces a line-count ratchet on `App.css`.
- Create or edit a colocated stylesheet next to your component—prefer CSS Modules (`MyPanel.module.css`) or a feature-scoped CSS file imported in `src/main.tsx` (following `ConfigChatWidget.css`, `SecurityAuditPanel.css`, `PmLookupPanel.css`, `simulatorsAndDiff.css`, `SslToIpsecPanel.css`, and `TsfExplorer.css`).
- When making non-trivial edits to an existing feature whose styles still live in `App.css`, gradually move those rules out into a colocated stylesheet and remove duplicates.

## 4. Visual Effects & Verification

- Keep visual effects restrained: prefer semantic tokens, clean borders, and subtle state transitions over heavy shadows, gradients, or animations.
- Avoid inline `style={{ ... }}` except for truly dynamic values (e.g. calculated widths/positions).
- Verify all frontend changes before finishing:

```bash
cd src/frontend
npm test
npm run lint
npm run build
```
