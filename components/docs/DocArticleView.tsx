import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowLeft, ArrowRight, Check, ChevronRight } from "lucide-react";
import type { ArticleMedia, DocArticle, DocCategory } from "@/lib/docs/types";
import { articleHref, categoryHref, neighbours, relatedArticles, videoPending } from "@/lib/docs/registry";
import { DocVideoPlayer } from "@/components/docs/DocVideoPlayer";
import { DocToc, SeekButton } from "@/components/docs/DocToc";

type Section = { id: string; title: string; body: ReactNode };

function Prose({ children }: { children: ReactNode }) {
  return <div className="text-[0.95rem] leading-relaxed text-[var(--text-secondary,var(--muted-foreground))]">{children}</div>;
}

/** Paragraphs split on blank lines; `code` in backticks. */
function Text({ value }: { value: string }) {
  return (
    <>
      {value.split(/\n{2,}/).map((paragraph, index) => (
        <p key={index} className={index ? "mt-3" : undefined}>
          {paragraph.split(/(`[^`]+`)/).map((part, i) =>
            part.startsWith("`") && part.endsWith("`")
              ? <code key={i} className="rounded bg-[var(--surface-2)] px-1 py-0.5 font-mono text-[0.85em] text-[var(--foreground)]">{part.slice(1, -1)}</code>
              : part,
          )}
        </p>
      ))}
    </>
  );
}

function Shot({ shot }: { shot: ArticleMedia["screenshots"][string] }) {
  return (
    <figure className="mt-3">
      <a href={shot.src} target="_blank" rel="noreferrer" className="block overflow-hidden rounded-[var(--r-md,12px)] border border-[var(--hairline)] bg-[var(--surface-2)]">
        <Image src={shot.src} alt={shot.alt} width={shot.width} height={shot.height} sizes="(min-width: 1024px) 720px, 100vw" className="h-auto w-full" />
      </a>
      <figcaption className="mt-1.5 text-xs text-[var(--muted-foreground)]">{shot.alt}</figcaption>
    </figure>
  );
}

export function DocArticleView({ article, category, media }: { article: DocArticle; category: DocCategory; media?: ArticleMedia }) {
  const { previous, next } = neighbours(article.id);
  const related = relatedArticles(article);
  const video = media?.video;
  const unavailable = "unavailable" in article.video ? article.video.unavailable : undefined;
  const pending = videoPending(article.id);
  const shots = media?.screenshots ?? {};

  const sections: Section[] = [];
  sections.push({ id: "introduction", title: "Introduction", body: <Prose><Text value={article.introduction} /></Prose> });
  if (article.problem) sections.push({ id: "problem", title: "The problem", body: <Prose><Text value={article.problem} /></Prose> });
  if (article.solution) {
    sections.push({
      id: "solution",
      title: "How Identity solves it",
      body: (
        <>
          <Prose><Text value={article.solution} /></Prose>
          {article.highlights?.length ? (
            <ul className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
              {article.highlights.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[var(--hairline)] text-[var(--accent)]">
                    <Check size={11} aria-hidden />
                  </span>
                  <span className="text-sm leading-relaxed text-[var(--foreground)]">{item}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ),
    });
  }
  if (article.useCases?.length) {
    sections.push({
      id: "use-cases",
      title: "Real-world use cases",
      body: (
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {article.useCases.map((useCase) => (
            <li key={useCase.title} className="rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] p-4">
              <p className="text-sm font-medium text-[var(--foreground)]">{useCase.title}</p>
              <p className="mt-1.5 text-sm leading-relaxed text-[var(--muted-foreground)]">{useCase.body}</p>
            </li>
          ))}
        </ul>
      ),
    });
  }
  if (article.steps?.length) {
    sections.push({
      id: "guide",
      title: "Step-by-step guide",
      body: (
        <ol className="flex flex-col gap-6">
          {article.steps.map((step, index) => (
            <li key={step.title} className="grid grid-cols-[2rem_minmax(0,1fr)] gap-3">
              <span className="flex h-7 w-7 items-center justify-center rounded-full border border-[var(--hairline)] font-mono text-xs text-[var(--accent)]">{index + 1}</span>
              <div>
                <p className="font-medium text-[var(--foreground)]">{step.title}</p>
                {step.body ? <div className="mt-1 text-sm leading-relaxed text-[var(--muted-foreground)]"><Text value={step.body} /></div> : null}
                {step.shot && shots[step.shot] ? <Shot shot={shots[step.shot]!} /> : null}
              </div>
            </li>
          ))}
        </ol>
      ),
    });
  }
  sections.push({
    id: "video",
    title: "Video walkthrough",
    body: video ? (
      <>
        <Prose><p>The video at the top of this page records the real workflow against an isolated test account. Jump to any moment from the transcript.</p></Prose>
        <ol aria-label="Transcript" className="mt-4 flex flex-col gap-2">
          {video.transcript.map((cue) => (
            <li key={cue.start} className="flex items-start gap-3 text-sm text-[var(--muted-foreground)]">
              <SeekButton seconds={cue.start} label={cue.text} />
              <span className="leading-relaxed">{cue.text}</span>
            </li>
          ))}
        </ol>
      </>
    ) : (
      <Prose><p>{pending ? "A recorded walkthrough of this feature is on its way; it will play here, with captions, chapters and a transcript, once it's published." : unavailable ?? "This walkthrough hasn't been recorded yet."}</p></Prose>
    ),
  });
  if (article.options?.length) {
    sections.push({
      id: "options",
      title: "Options and controls",
      body: (
        <dl className="divide-y divide-[var(--hairline)] rounded-[var(--r-lg)] border border-[var(--hairline)]">
          {article.options.map((option) => (
            <div key={option.name} className="grid grid-cols-1 gap-1 px-4 py-3 sm:grid-cols-[12rem_minmax(0,1fr)] sm:gap-4">
              <dt className="text-sm font-medium text-[var(--foreground)]">{option.name}</dt>
              <dd className="text-sm leading-relaxed text-[var(--muted-foreground)]"><Text value={option.description} /></dd>
            </div>
          ))}
        </dl>
      ),
    });
  }
  if (article.permissions?.length) {
    sections.push({
      id: "permissions",
      title: "Permissions",
      body: (
        <table className="w-full border-collapse overflow-hidden rounded-[var(--r-lg)] text-left text-sm">
          <thead>
            <tr className="border-b border-[var(--hairline)] font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]">
              <th scope="col" className="py-2 pr-4 font-normal">Who</th>
              <th scope="col" className="py-2 font-normal">What they can do</th>
            </tr>
          </thead>
          <tbody>
            {article.permissions.map((row) => (
              <tr key={row.who} className="border-b border-[var(--hairline)] align-top">
                <th scope="row" className="py-2.5 pr-4 font-medium text-[var(--foreground)]">{row.who}</th>
                <td className="py-2.5 leading-relaxed text-[var(--muted-foreground)]">{row.can}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ),
    });
  }
  if (article.advanced?.length) {
    sections.push({
      id: "advanced",
      title: "Advanced capabilities",
      body: (
        <ul className="flex flex-col gap-2.5">
          {article.advanced.map((item) => (
            <li key={item} className="flex gap-3 text-sm leading-relaxed text-[var(--muted-foreground)]">
              <span aria-hidden className="mt-2 h-1 w-1 shrink-0 rounded-full bg-[var(--accent)]" />
              <span><Text value={item} /></span>
            </li>
          ))}
        </ul>
      ),
    });
  }
  if (article.troubleshooting?.length) {
    sections.push({
      id: "troubleshooting",
      title: "Troubleshooting",
      body: (
        <div className="flex flex-col gap-2">
          {article.troubleshooting.map((item, index) => (
            <details key={item.problem} id={`fix-${index + 1}`} className="group rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer list-none text-sm font-medium text-[var(--foreground)] marker:hidden">
                <span className="flex items-center justify-between gap-3">
                  {item.problem}
                  <ChevronRight size={14} aria-hidden className="shrink-0 text-[var(--muted-foreground)] transition-transform group-open:rotate-90" />
                </span>
              </summary>
              <div className="mt-2 text-sm leading-relaxed text-[var(--muted-foreground)]"><Text value={item.solution} /></div>
            </details>
          ))}
        </div>
      ),
    });
  }
  if (article.faqs?.length) {
    sections.push({
      id: "faq",
      title: "Frequently asked questions",
      body: (
        <div className="flex flex-col gap-2">
          {article.faqs.map((item, index) => (
            <details key={item.question} id={`faq-${index + 1}`} className="group rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer list-none text-sm font-medium text-[var(--foreground)]">{item.question}</summary>
              <div className="mt-2 text-sm leading-relaxed text-[var(--muted-foreground)]"><Text value={item.answer} /></div>
            </details>
          ))}
        </div>
      ),
    });
  }
  if (related.length) {
    sections.push({
      id: "related",
      title: "Related features",
      body: (
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {related.map((item) => (
            <li key={item.id}>
              <Link href={articleHref(item)} className="group block h-full rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface)] p-4 transition-colors hover:border-[var(--accent)]">
                <span className="flex items-center justify-between gap-2 text-sm font-medium text-[var(--foreground)]">
                  {item.title}
                  <ArrowRight size={14} aria-hidden className="text-[var(--muted-foreground)] transition-transform group-hover:translate-x-0.5" />
                </span>
                <span className="mt-1 block text-sm leading-snug text-[var(--muted-foreground)]">{item.summary}</span>
              </Link>
            </li>
          ))}
        </ul>
      ),
    });
  }

  return (
    <div className="mx-auto flex w-full max-w-6xl gap-10 px-4 py-8 sm:px-6 sm:py-10">
      <article className="min-w-0 max-w-3xl flex-1" data-doc-article={article.id}>
        <nav aria-label="Breadcrumb">
          <ol className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
            <li><Link href="/docs" className="hover:text-[var(--foreground)]">Docs</Link></li>
            <li aria-hidden>/</li>
            <li><Link href={categoryHref(category.id)} className="hover:text-[var(--foreground)]">{category.title}</Link></li>
            <li aria-hidden>/</li>
            <li aria-current="page" className="text-[var(--foreground)]">{article.title}</li>
          </ol>
        </nav>

        <header className="mt-6">
          <p className="eyebrow">{category.title} — {article.kind === "feature" ? "Feature" : "Guide"}</p>
          <h1 className="mt-3 font-display text-4xl font-semibold tracking-tight text-[var(--foreground)] md:text-5xl">{article.title}</h1>
          <p className="mt-4 max-w-2xl text-base leading-relaxed text-[var(--muted-foreground)]">{article.summary}</p>
          {article.location ? (
            <p className="mt-4 inline-flex flex-wrap items-center gap-2 text-xs text-[var(--muted-foreground)]">
              <span className="font-mono uppercase tracking-[0.12em]">Find it</span>
              <span className="rounded-md border border-[var(--hairline)] bg-[var(--surface-2)] px-2 py-0.5 text-[var(--foreground)]">{article.location}</span>
            </p>
          ) : null}
        </header>

        <div className="mt-8">
          <DocVideoPlayer title={article.title} video={video} unavailable={unavailable} pending={pending} />
        </div>

        <div className="mt-12 flex flex-col gap-12">
          {sections.map((section, index) => (
            <section key={section.id} id={section.id} aria-labelledby={`${section.id}-title`} className="scroll-mt-6">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">{String(index + 1).padStart(2, "0")}</p>
              <h2 id={`${section.id}-title`} className="mt-1 font-display text-2xl font-semibold tracking-tight text-[var(--foreground)]">{section.title}</h2>
              <div className="mt-4">{section.body}</div>
            </section>
          ))}
        </div>

        <details className="mt-12 rounded-[var(--r-lg)] border border-[var(--hairline)] px-4 py-3 text-sm">
          <summary className="cursor-pointer text-[var(--muted-foreground)]">Under the hood</summary>
          <p className="mt-2 text-[var(--muted-foreground)]">Written from these parts of the source:</p>
          <ul className="mt-2 flex flex-col gap-1 font-mono text-xs text-[var(--foreground)]">
            {article.sources.map((source) => <li key={source}>{source}</li>)}
          </ul>
          {media ? (
            <p className="mt-3 text-xs text-[var(--muted-foreground)]">
              Screenshots and video captured {new Date(media.capturedAt).toISOString().slice(0, 10)}
              {media.verified ? ", with every step checked." : "; some steps could not be checked."}
            </p>
          ) : null}
        </details>

        <nav aria-label="Previous and next" className="mt-12 grid grid-cols-1 gap-3 border-t border-[var(--hairline)] pt-8 sm:grid-cols-2">
          {previous ? (
            <Link href={articleHref(previous)} rel="prev" className="group rounded-[var(--r-lg)] border border-[var(--hairline)] p-4 hover:border-[var(--accent)]">
              <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]"><ArrowLeft size={12} aria-hidden /> Previous</span>
              <span className="mt-1 block font-medium text-[var(--foreground)] group-hover:text-[var(--accent)]">{previous.title}</span>
            </Link>
          ) : <span />}
          {next ? (
            <Link href={articleHref(next)} rel="next" className="group rounded-[var(--r-lg)] border border-[var(--hairline)] p-4 text-right hover:border-[var(--accent)]">
              <span className="flex items-center justify-end gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--muted-foreground)]">Next <ArrowRight size={12} aria-hidden /></span>
              <span className="mt-1 block font-medium text-[var(--foreground)] group-hover:text-[var(--accent)]">{next.title}</span>
            </Link>
          ) : null}
        </nav>
      </article>

      <aside className="hidden w-56 shrink-0 xl:block">
        <div className="sticky top-8">
          <DocToc
            sections={sections.map(({ id, title }) => ({ id, title }))}
            chapters={video?.chapters ?? []}
            related={related.map((item) => ({ title: item.title, href: articleHref(item) }))}
          />
        </div>
      </aside>
    </div>
  );
}
