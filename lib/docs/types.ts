/**
 * The documentation model. Articles are plain data — no React, no server code —
 * so the Docs UI, the search index, the capture pipeline and the regeneration
 * scan all read the same source. See docs/DOCS-SYSTEM.md.
 */

export type CategoryId =
  | "getting-started"
  | "signing-in"
  | "account"
  | "security"
  | "privacy"
  | "spaces"
  | "enterprise"
  | "developers"
  | "admin"
  | "help";

export type DocCategory = {
  id: CategoryId;
  title: string;
  /** One line under the category title on its index page. */
  blurb: string;
};

/** Who can do what. `who` is a role name ("Member", "Admin", "Owner", "Identity admin") or a plain phrase. */
export type DocPermission = { who: string; can: string };

export type DocStep = {
  title: string;
  body?: string;
  /** Key of a screenshot the capture scenario saved for this article. */
  shot?: string;
};

export type DocArticle = {
  /** Stable id and URL segment; also names the article's video and screenshots. */
  id: string;
  category: CategoryId;
  title: string;
  /** One sentence: the sidebar tooltip, search snippet and page lead. */
  summary: string;
  /** "feature" articles carry all eleven sections; "guide" articles (overview, help) pick their own. */
  kind: "feature" | "guide";
  /** Where it lives in the app, as a route pattern or a path through the UI. */
  location?: string;

  introduction: string;
  problem?: string;
  solution?: string;
  /** Short case-study bullets shown under the solution. */
  highlights?: string[];
  useCases?: { title: string; body: string }[];
  steps?: DocStep[];
  options?: { name: string; description: string }[];
  permissions?: DocPermission[];
  advanced?: string[];
  troubleshooting?: { problem: string; solution: string }[];
  faqs?: { question: string; answer: string }[];
  related?: string[];

  /**
   * Source files this article describes, repo-relative. The regeneration scan
   * fingerprints them to tell when the article, its screenshots or its video
   * may be out of date. Directories cover everything under them.
   */
  sources: string[];
  /** Extra search terms that don't appear in the text. */
  keywords?: string[];
  /**
   * The capture scenario that records this article's video, or why there is no
   * video. A feature that can't be shown safely is marked, never faked.
   */
  video: { scenario: string } | { unavailable: string };
};

export type VideoChapter = { title: string; start: number };

/** What the capture + render pipeline produced for one article (src/docs/media.json). */
export type ArticleMedia = {
  video?: {
    src: string;
    poster: string;
    captions: string;
    duration: number;
    chapters: VideoChapter[];
    /** The caption cues, also shown as a transcript under the video. */
    transcript: { start: number; end: number; text: string }[];
  };
  screenshots: Record<string, { src: string; alt: string; width: number; height: number }>;
  /** Fingerprint of the article's sources when the media was captured. */
  fingerprint: string;
  capturedAt: string;
  /** Every expectation in the scenario passed while recording. */
  verified: boolean;
};

export type MediaManifest = Record<string, ArticleMedia>;
