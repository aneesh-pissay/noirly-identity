"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { VideoChapter } from "@/lib/docs/types";
import { seekDocVideo } from "@/components/docs/DocVideoPlayer";

type Props = {
  sections: { id: string; title: string }[];
  chapters: VideoChapter[];
  related: { title: string; href: string }[];
};

function clock(seconds: number) {
  const s = Math.floor(seconds);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Right rail: the article's sections (the one in view highlighted), video chapters and related reading. */
export function DocToc({ sections, chapters, related }: Props) {
  const [current, setCurrent] = useState(sections[0]?.id);

  useEffect(() => {
    const root = document.getElementById("docs-main");
    const targets = sections.map((section) => document.getElementById(section.id)).filter((el): el is HTMLElement => Boolean(el));
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (visible[0]) setCurrent(visible[0].target.id);
    }, { root, rootMargin: "0px 0px -70% 0px" });
    targets.forEach((target) => observer.observe(target));
    return () => observer.disconnect();
  }, [sections]);

  return (
    <div className="flex flex-col gap-7 text-sm">
      <nav aria-label="On this page">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">On this page</p>
        <ul className="mt-3 flex flex-col gap-1 border-l border-[var(--hairline)]">
          {sections.map((section) => (
            <li key={section.id}>
              <a href={`#${section.id}`} aria-current={current === section.id ? "location" : undefined}
                className={`-ml-px block border-l py-0.5 pl-3 transition-colors ${current === section.id ? "border-[var(--accent)] text-[var(--accent)]" : "border-transparent text-[var(--muted-foreground)] hover:text-[var(--foreground)]"}`}>
                {section.title}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      {chapters.length > 1 ? (
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Video chapters</p>
          <ul className="mt-3 flex flex-col gap-1">
            {chapters.map((chapter) => (
              <li key={chapter.start}>
                <button type="button" onClick={() => seekDocVideo(chapter.start)}
                  className="flex w-full items-baseline justify-between gap-3 rounded-md py-0.5 text-left text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
                  <span>{chapter.title}</span>
                  <span className="font-mono text-[11px]">{clock(chapter.start)}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {related.length ? (
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Related</p>
          <ul className="mt-3 flex flex-col gap-1">
            {related.map((item) => (
              <li key={item.href}>
                <Link href={item.href} className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]">{item.title}</Link>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

/** "Play from here" on a transcript line or chapter in the article body. */
export function SeekButton({ seconds, label }: { seconds: number; label: string }) {
  return (
    <button type="button" onClick={() => seekDocVideo(seconds)} aria-label={`Play from ${clock(seconds)}: ${label}`}
      className="shrink-0 rounded-md border border-[var(--hairline)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--muted-foreground)] hover:border-[var(--accent)] hover:text-[var(--accent)]">
      {clock(seconds)}
    </button>
  );
}
