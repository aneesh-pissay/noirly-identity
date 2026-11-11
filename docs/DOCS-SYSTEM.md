# Docs system

The in-app Docs (`/docs`) explain every Identity feature with an article, built the same way as Noirly Flow's Docs. This file is how it fits together and how to keep it current.

## Pieces

| Piece | Where | What it is |
| --- | --- | --- |
| Articles | `lib/docs/content/*.ts` | One typed `DocArticle` per feature or guide (`lib/docs/types.ts`). Plain data: no React, no server code. |
| Registry | `lib/docs/registry.ts` | Category order, sidebar tree, URLs, previous/next, related links, media lookup. |
| Search | `lib/docs/search.ts` | Client-side index over titles, summaries, steps, options, troubleshooting and FAQs. |
| Media manifest | `lib/docs/media.json` | Screenshots and video per article. Empty until the capture pipeline is ported (below). |
| Inventory | `lib/docs/inventory.json` | Written by `npm run docs:scan -- --write`: every article with its sources and fingerprint, plus every page, API route and component found in the code. The reviewed baseline. |
| UI | `app/(docs)/**`, `components/docs/*` | Public pages under the site header, linked from the landing page and the account page. Sidebar with search, article view, video player, "On this page" panel. |
| Coverage scan | `docs-pipeline/scan.ts` | Compares the code with the articles. |

An article's `id` is its URL segment (`/docs/<category>/<id>`) and names its video and screenshot folder. `sources` lists the files it describes; their fingerprint (`docs-pipeline/lib/fingerprint.ts`) tells the scan when an article may be out of date.

## Categories

Getting started, Signing in, Your account, Security, Privacy & data, Spaces, Enterprise (single sign-on and provisioning), For developers, Administration, Help.

## Article shape

Feature articles carry all eleven sections: introduction, problem, solution (with highlights), use cases, step-by-step guide, video walkthrough, options, permissions, advanced capabilities, troubleshooting and related features. Guides (overview, code guides, help) pick their own. `tests/docs.test.ts` fails if a feature section is missing, a related link or source file doesn't exist, a video is named after another article, or search stops finding the obvious answers.

Write only what the code does, and use the labels on screen: check them against the components before writing a step.

A feature that can't be recorded safely has `video: { unavailable: "<why>" }` and the page says so. Nothing is faked. Those are: passkeys (browser prompts), providers and single sign-on (real third-party accounts), phone verification (real texts), domain verification (real DNS), SCIM (a real directory), the mobile app approval (a real phone), and the consent screen (needs a second app).

## Videos and screenshots

The Playwright capture and Remotion render pipeline from Flow (`docs-pipeline/capture`, `docs-pipeline/video`, `docs-pipeline/render.ts`, `playwright.docs.config.ts`) hasn't been ported yet: Identity has no isolated e2e server to record against. Until it is, articles with a `scenario` show "Video coming soon", and no screenshots appear. To port it, set up an isolated e2e server (its own database, test-only sessions, email to files), then copy Flow's pipeline and write one scenario per article named in `video.scenario`.

Videos would be hosted like Flow's: `R2_PUBLIC_URL` → `<R2_PUBLIC_URL>/doc-videos/<article-id>.mp4` (`lib/docs/video-host.ts`), added to the CSP's `media-src`.

## Keeping it current

1. `npm run docs:scan` lists articles whose sources changed (review the text), code no article covers (a new feature?), and articles whose sources are gone.
2. Update the affected articles by hand (or ask Claude Code to, from the diff).
3. `npm run docs:scan -- --write` once the text is reviewed. Nothing is ever marked current automatically.
4. `npx vitest run tests/docs.test.ts`.

`NOT_DOCUMENTED` in `docs-pipeline/scan.ts` lists code with no user-facing feature of its own, and why.

The developer reference stays in `docs/INTEGRATION.md`, `docs/SSO.md` and `docs/PROVISIONING.md`; the in-app articles summarise them for people and point there for detail.
