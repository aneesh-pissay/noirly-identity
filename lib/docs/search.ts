import type { DocArticle } from "@/lib/docs/types";

/**
 * One searchable entry: an article, or a step, troubleshooting fix or FAQ
 * inside one (so a hit can jump straight to its section).
 */
export type SearchDoc = {
  href: string;
  article: string;
  /** The entry's own heading — the article title for article-level entries. */
  title: string;
  /** Which part of the article: "Article", "Guide", "Troubleshooting", "FAQ", "Options". */
  section: string;
  text: string;
  keywords: string;
};

export function buildSearchDocs(articles: DocArticle[], hrefOf: (article: DocArticle) => string): SearchDoc[] {
  const docs: SearchDoc[] = [];
  for (const article of articles) {
    const href = hrefOf(article);
    const base = { article: article.title, keywords: (article.keywords ?? []).join(" ") };
    docs.push({
      ...base,
      href,
      title: article.title,
      section: "Article",
      text: [article.summary, article.introduction, article.problem, article.solution].filter(Boolean).join(" "),
    });
    if (article.steps?.length) {
      docs.push({
        ...base,
        href: `${href}#guide`,
        title: `How to: ${article.title}`,
        section: "Guide",
        text: article.steps.map((step) => `${step.title} ${step.body ?? ""}`).join(" "),
      });
    }
    if (article.options?.length) {
      docs.push({
        ...base,
        href: `${href}#options`,
        title: `${article.title} options`,
        section: "Options",
        text: article.options.map((option) => `${option.name} ${option.description}`).join(" "),
      });
    }
    article.troubleshooting?.forEach((item, index) => {
      docs.push({ ...base, href: `${href}#fix-${index + 1}`, title: item.problem, section: "Troubleshooting", text: item.solution });
    });
    article.faqs?.forEach((item, index) => {
      docs.push({ ...base, href: `${href}#faq-${index + 1}`, title: item.question, section: "FAQ", text: item.answer });
    });
  }
  return docs;
}

const tokenize = (value: string) =>
  value.toLowerCase().normalize("NFKD").replace(/[^\p{L}\p{N}@#]+/gu, " ").split(" ").filter((token) => token.length > 1);

/**
 * Every query word must appear somewhere in the entry. Matches in the title
 * count most, then keywords and the article name, then body text.
 */
export function searchDocs(docs: SearchDoc[], query: string, limit = 20): SearchDoc[] {
  const words = tokenize(query);
  if (!words.length) return [];
  const scored: { doc: SearchDoc; score: number }[] = [];
  for (const doc of docs) {
    const title = doc.title.toLowerCase();
    const titleWords = tokenize(doc.title);
    const meta = `${doc.keywords} ${doc.article}`.toLowerCase();
    const text = doc.text.toLowerCase();
    let score = 0;
    let all = true;
    for (const word of words) {
      let best = 0;
      if (titleWords.includes(word)) best = 12;
      else if (titleWords.some((w) => w.startsWith(word))) best = 8;
      else if (title.includes(word)) best = 6;
      else if (meta.includes(word)) best = 4;
      else if (text.includes(word)) best = 1;
      if (!best) { all = false; break; }
      score += best;
    }
    if (!all) continue;
    if (doc.section === "Article") score += 2;
    scored.push({ doc, score });
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, limit).map((entry) => entry.doc);
}

/** A short excerpt of `text` around the first query word. */
export function snippet(text: string, query: string, size = 140): string {
  const words = tokenize(query);
  const lower = text.toLowerCase();
  const at = words.map((word) => lower.indexOf(word)).filter((i) => i >= 0).sort((a, b) => a - b)[0] ?? 0;
  const start = Math.max(0, at - 40);
  const cut = text.slice(start, start + size).trim();
  return `${start > 0 ? "…" : ""}${cut}${start + size < text.length ? "…" : ""}`;
}
