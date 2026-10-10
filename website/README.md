# SP-DECODE Website

Official multilingual, mobile-first product landing page for the native offline SP-DECODE Android app and its related self-hosted Telegram bot. The design tracks the repository's [Android design system](../docs/android/DESIGN_SYSTEM.md) with AMOLED surfaces, subdued blue accents and outline icons.

## Stack

- Next.js 16 App Router + TypeScript
- React 19
- Tailwind CSS 4 + project CSS tokens
- Lucide vector icons
- Local dictionaries for Spanish, English, Brazilian Portuguese and Arabic (RTL)
- No database, no authentication, no analytics script and **no remote decoding or file uploads**

## Pages

Each locale has a landing page plus `features`, `privacy`, `terms`, `license` and `support`. The home page redirects to Spanish. Locale routes support direct URLs: `/es`, `/en`, `/pt-BR`, `/ar`. The phone UI shown in the hero is a **clearly labeled illustrative mockup**, not a screenshot of the installed app or an interactive decoder.

## Local development

```bash
cd website
npm install
npm run typecheck
npm run build
npm run dev
```

Use Node.js 20.9 or newer. The root SP-DECODE repository's Node.js files belong to the Telegram bot; this website has its **own package.json** and lockfile.

## Vercel deployment

- Connect repository `Gh0stDeveloper/SP-DECODE`.
- Set **Root Directory** to `website`.
- Framework: **Next.js**, Node 22.
- Set `NEXT_PUBLIC_SITE_URL` to the *actual live domain* for canonical URLs and sitemap. This variable is public and **must not contain secrets**.
- Deploy from the GitHub integration. PR branches produce previews; `main` is production.
- Once Vercel has an actual URL, update repository GitHub About Website metadata if authorized.

## Product facts / publication safety

- Stable APK [v1.0.4](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4); permanently signed preview [v1.0.5-rc.1](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1).
- **60 registered suffixes** does not mean every exporter version is verified.
- v1.0.5 remains **NO-GO stable** pending real-file parity cases. Refer to `release/android-readiness.json`.
- The repository currently has **no top-level LICENSE**. Website licensing text states that explicitly and does not invent a grant of redistribution rights.
- App privacy is separate from website hosting (Vercel) and the Telegram bot's operator/Telegram processing. Review the site's policy text before public commercial distribution.
