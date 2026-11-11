import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ARTICLES, CATEGORIES, capturedMediaFor, getArticle, mediaFor, navTree, VIDEOS_ENABLED } from "@/lib/docs/registry";
import { buildSearchDocs, searchDocs } from "@/lib/docs/search";

const FEATURE_SECTIONS = ["problem", "solution", "useCases", "steps", "options", "permissions", "advanced", "troubleshooting", "related"] as const;

describe("docs content", () => {
  it("gives every article a unique id in a known category", () => {
    const ids = ARTICLES.map((article) => article.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const article of ARTICLES) {
      expect(CATEGORIES.map((c) => c.id)).toContain(article.category);
      expect(article.id).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("fills in all eleven sections for every feature article", () => {
    for (const article of ARTICLES.filter((a) => a.kind === "feature")) {
      for (const section of FEATURE_SECTIONS) {
        const value = article[section];
        expect(value, `${article.id} is missing ${section}`).toBeTruthy();
        if (Array.isArray(value)) expect(value.length, `${article.id} has an empty ${section}`).toBeGreaterThan(0);
      }
    }
  });

  it("links only to articles that exist, never to itself", () => {
    for (const article of ARTICLES) {
      for (const id of article.related ?? []) {
        expect(getArticle(id), `${article.id} links to unknown “${id}”`).toBeDefined();
        expect(id).not.toBe(article.id);
      }
    }
  });

  it("points at source files that exist (repo-relative)", () => {
    for (const article of ARTICLES) {
      expect(article.sources.length, `${article.id} has no sources`).toBeGreaterThan(0);
      for (const source of article.sources) {
        expect(existsSync(source), `${article.id}: ${source} doesn't exist`).toBe(true);
      }
    }
  });

  it("names each video after its article, or says why there is none", () => {
    for (const article of ARTICLES) {
      if ("scenario" in article.video) expect(article.video.scenario).toBe(article.id);
      else expect(article.video.unavailable.length).toBeGreaterThan(20);
    }
  });

  it("only references screenshots and videos that were captured for the article", () => {
    for (const article of ARTICLES) {
      const media = capturedMediaFor(article.id);
      if (!media) continue;
      if (media.video) expect(media.video.src).toBe(`/docs/videos/${article.id}.mp4`);
      for (const shot of Object.values(media.screenshots)) {
        expect(shot.src.startsWith(`/docs/screenshots/${article.id}/`)).toBe(true);
        expect(existsSync(`public${shot.src}`), shot.src).toBe(true);
      }
    }
  });

  it("serves videos only when a video host is configured", () => {
    const recorded = ARTICLES.find((article) => capturedMediaFor(article.id)?.video);
    if (!recorded) return;
    const shown = mediaFor(recorded.id)?.video;
    if (VIDEOS_ENABLED) expect(shown?.src).toMatch(new RegExp(`/${recorded.id}\\.mp4$`));
    else expect(shown).toBeUndefined();
  });

  it("puts every article in the sidebar exactly once", () => {
    const linked = navTree().flatMap((category) => category.articles.map((a) => a.id));
    expect(linked.sort()).toEqual(ARTICLES.map((a) => a.id).sort());
  });
});

describe("docs search", () => {
  const docs = buildSearchDocs(ARTICLES, (a) => `/docs/${a.category}/${a.id}`);

  it("ranks the feature whose name matches first", () => {
    expect(searchDocs(docs, "passkeys")[0]?.href).toBe("/docs/signing-in/passkeys");
    expect(searchDocs(docs, "scim")[0]?.href).toBe("/docs/enterprise/scim-provisioning");
  });

  it("finds troubleshooting entries and FAQs", () => {
    expect(searchDocs(docs, "lost my phone").some((d) => d.section === "Troubleshooting")).toBe(true);
    expect(searchDocs(docs, "light theme").some((d) => d.section === "FAQ")).toBe(true);
  });

  it("finds steps and keywords", () => {
    expect(searchDocs(docs, "okta")[0]?.article).toMatch(/identity provider|organization|SCIM/i);
    expect(searchDocs(docs, "Check DNS now").some((d) => d.article === "Business domains")).toBe(true);
  });

  it("needs every word to match", () => {
    expect(searchDocs(docs, "webhooks zebra")).toEqual([]);
  });
});

describe("docs video host", () => {
  it("plays from the R2 bucket's Public Development URL, and is off without one", async () => {
    const { docsVideoBaseUrl } = await import("@/lib/docs/video-host");
    expect(docsVideoBaseUrl("https://pub-abc123.r2.dev")).toBe("https://pub-abc123.r2.dev/doc-videos");
    expect(docsVideoBaseUrl(" https://pub-abc123.r2.dev/ ")).toBe("https://pub-abc123.r2.dev/doc-videos");
    expect(docsVideoBaseUrl("")).toBe("");
    expect(docsVideoBaseUrl("not a url")).toBe("");
  });
});
