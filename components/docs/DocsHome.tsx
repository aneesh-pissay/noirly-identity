import Link from "next/link";
import { ArrowRight, PlayCircle } from "lucide-react";
import type { DocCategory } from "@/lib/docs/types";
import { ARTICLES, CATEGORIES, articleHref, articlesIn, categoryHref, getArticle, mediaFor, VIDEOS_ENABLED } from "@/lib/docs/registry";

const START_HERE = ["overview", "signing-in", "two-step-verification", "spaces"];

function hasVideo(id: string) {
  return Boolean(mediaFor(id)?.video);
}

/** /docs — the front page: what's here, where to start, and every category. */
export function DocsHome() {
  const features = ARTICLES.filter((article) => article.kind === "feature");
  const videos = ARTICLES.filter((article) => hasVideo(article.id)).length;
  const start = START_HERE.map((id) => getArticle(id)).filter((a) => a !== undefined);

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-12 px-4 py-8 sm:px-6 sm:py-12">
      <header>
        <p className="eyebrow">Noirly Identity — Documentation</p>
        <h1 className="mt-4 font-display text-4xl font-semibold tracking-tight text-[var(--foreground)] md:text-6xl">Identity, explained.</h1>
        <p className="mt-5 max-w-2xl text-base leading-relaxed text-[var(--muted-foreground)]">
          Every feature in Identity: what it does, the problem it solves, how to use it step by step, and (where it can be recorded safely) a short video of it
          working. Search with <kbd className="rounded border border-[var(--hairline)] px-1 font-mono text-xs">/</kbd> or browse the sidebar.
        </p>
        <dl className="mt-8 flex flex-wrap gap-x-10 gap-y-4">
          <div>
            <dt className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Features documented</dt>
            <dd className="mt-1 font-display text-3xl font-semibold text-[var(--foreground)]">{features.length}</dd>
          </div>
          <div>
            <dt className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Video walkthroughs</dt>
            <dd className="mt-1 font-display text-3xl font-semibold text-[var(--foreground)]">{VIDEOS_ENABLED ? videos : "Coming soon"}</dd>
          </div>
          <div>
            <dt className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Categories</dt>
            <dd className="mt-1 font-display text-3xl font-semibold text-[var(--foreground)]">{CATEGORIES.length}</dd>
          </div>
        </dl>
      </header>

      <section aria-labelledby="start-here">
        <h2 id="start-here" className="font-display text-2xl font-semibold tracking-tight text-[var(--foreground)]">Start here</h2>
        <ul className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {start.map((article) => (
            <li key={article.id}>
              <Link href={articleHref(article)} className="group flex h-full flex-col rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] p-5 transition-colors hover:border-[var(--accent)]">
                <span className="flex items-center justify-between gap-3 font-medium text-[var(--foreground)]">
                  {article.title}
                  <ArrowRight size={15} aria-hidden className="text-[var(--muted-foreground)] transition-transform group-hover:translate-x-0.5" />
                </span>
                <span className="mt-1.5 text-sm leading-relaxed text-[var(--muted-foreground)]">{article.summary}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="all-categories">
        <h2 id="all-categories" className="font-display text-2xl font-semibold tracking-tight text-[var(--foreground)]">Everything in Identity</h2>
        <div className="mt-5 grid grid-cols-1 gap-x-8 gap-y-10 md:grid-cols-2">
          {CATEGORIES.map((category) => (
            <div key={category.id}>
              <Link href={categoryHref(category.id)} className="font-mono text-[11px] uppercase tracking-[0.16em] text-[var(--accent)] hover:underline">{category.title}</Link>
              <p className="mt-1 text-sm text-[var(--muted-foreground)]">{category.blurb}</p>
              <ul className="mt-3 flex flex-col divide-y divide-[var(--hairline)] border-y border-[var(--hairline)]">
                {articlesIn(category.id).map((article) => (
                  <li key={article.id}>
                    <Link href={articleHref(article)} className="flex items-center justify-between gap-3 py-2 text-sm text-[var(--foreground)] hover:text-[var(--accent)]">
                      {article.title}
                      {hasVideo(article.id) ? <PlayCircle size={14} aria-label="Has a video" className="shrink-0 text-[var(--muted-foreground)]" /> : null}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

/** /docs/:category — the category's articles as cards. */
export function DocsCategory({ category }: { category: DocCategory }) {
  const index = CATEGORIES.findIndex((c) => c.id === category.id);
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-10 px-4 py-8 sm:px-6 sm:py-12">
      <nav aria-label="Breadcrumb" className="font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
        <Link href="/docs" className="hover:text-[var(--foreground)]">Docs</Link> <span aria-hidden>/</span>{" "}
        <span aria-current="page" className="text-[var(--foreground)]">{category.title}</span>
      </nav>
      <header>
        <p className="eyebrow">{String(index + 1).padStart(2, "0")} — Category</p>
        <h1 className="mt-3 font-display text-4xl font-semibold tracking-tight text-[var(--foreground)] md:text-5xl">{category.title}</h1>
        <p className="mt-4 max-w-2xl text-base leading-relaxed text-[var(--muted-foreground)]">{category.blurb}</p>
      </header>
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {articlesIn(category.id).map((article) => (
          <li key={article.id}>
            <Link href={articleHref(article)} className="group flex h-full flex-col rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] p-5 transition-colors hover:border-[var(--accent)]">
              <span className="flex items-center justify-between gap-3 font-medium text-[var(--foreground)]">
                {article.title}
                {hasVideo(article.id) ? <PlayCircle size={15} aria-label="Has a video" className="shrink-0 text-[var(--muted-foreground)]" /> : null}
              </span>
              <span className="mt-1.5 text-sm leading-relaxed text-[var(--muted-foreground)]">{article.summary}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
