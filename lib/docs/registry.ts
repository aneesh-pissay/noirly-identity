import type { ArticleMedia, CategoryId, DocArticle, DocCategory, MediaManifest } from "@/lib/docs/types";
import media from "@/lib/docs/media.json";
import { docsVideoBaseUrl } from "@/lib/docs/video-host";
import { gettingStarted } from "@/lib/docs/content/getting-started";
import { signingIn } from "@/lib/docs/content/signing-in";
import { account } from "@/lib/docs/content/account";
import { security } from "@/lib/docs/content/security";
import { privacy } from "@/lib/docs/content/privacy";
import { spaces } from "@/lib/docs/content/spaces";
import { enterprise } from "@/lib/docs/content/enterprise";
import { developers } from "@/lib/docs/content/developers";
import { admin } from "@/lib/docs/content/admin";
import { help } from "@/lib/docs/content/help";

/** Sidebar order. */
export const CATEGORIES: DocCategory[] = [
  { id: "getting-started", title: "Getting started", blurb: "What Noirly Identity is, creating an account, and finding your way around." },
  { id: "signing-in", title: "Signing in", blurb: "Passwords, passkeys, Google and other providers, emailed links, and a second step." },
  { id: "account", title: "Your account", blurb: "Your profile, addresses, phone, preferences, merging and closing." },
  { id: "security", title: "Security", blurb: "Devices, session length, activity, alerts, freezing and recovery." },
  { id: "privacy", title: "Privacy & data", blurb: "What Identity holds, the apps you've let in, and getting your data." },
  { id: "spaces", title: "Spaces", blurb: "One team across every Noirly app: members, invitations, domains, teams and access." },
  { id: "enterprise", title: "Enterprise", blurb: "Single sign-on with your own identity provider, and directory provisioning." },
  { id: "developers", title: "For developers", blurb: "Register apps and APIs, environments, tokens, logout and webhooks." },
  { id: "admin", title: "Administration", blurb: "Audit, account protection, deletions, claim review, keys and compliance." },
  { id: "help", title: "Help", blurb: "Fixes for common problems and answers to common questions." },
];

const BY_CATEGORY: Record<CategoryId, DocArticle[]> = {
  "getting-started": gettingStarted,
  "signing-in": signingIn,
  "account": account,
  "security": security,
  "privacy": privacy,
  "spaces": spaces,
  "enterprise": enterprise,
  "developers": developers,
  "admin": admin,
  "help": help,
};

/** Every article, in reading order. */
export const ARTICLES: DocArticle[] = CATEGORIES.flatMap((category) => BY_CATEGORY[category.id]);

const INDEX = new Map(ARTICLES.map((article) => [article.id, article]));

export function getArticle(id: string): DocArticle | undefined {
  return INDEX.get(id);
}

export function getCategory(id: string): DocCategory | undefined {
  return CATEGORIES.find((category) => category.id === id);
}

export function articlesIn(category: CategoryId): DocArticle[] {
  return BY_CATEGORY[category];
}

export function articleHref(article: Pick<DocArticle, "id" | "category">): string {
  return `/docs/${article.category}/${article.id}`;
}

export function categoryHref(category: CategoryId): string {
  return `/docs/${category}`;
}

/** The articles either side in reading order. */
export function neighbours(id: string): { previous?: DocArticle; next?: DocArticle } {
  const at = ARTICLES.findIndex((article) => article.id === id);
  return { previous: ARTICLES[at - 1], next: ARTICLES[at + 1] };
}

export function relatedArticles(article: DocArticle): DocArticle[] {
  return (article.related ?? []).map((id) => INDEX.get(id)).filter((a): a is DocArticle => Boolean(a));
}

const MEDIA = media as MediaManifest;

/** Where the tutorial MP4s play from (see video-host.ts). Posters and captions stay in /public. */
export const VIDEO_BASE_URL = docsVideoBaseUrl();
export const VIDEOS_ENABLED = Boolean(VIDEO_BASE_URL);

/** What the pipeline captured, exactly as recorded in media.json. */
export function capturedMediaFor(id: string): ArticleMedia | undefined {
  return MEDIA[id];
}

/** The article's media as the Docs should show it: video only when a host is configured. */
export function mediaFor(id: string): ArticleMedia | undefined {
  const captured = MEDIA[id];
  if (!captured?.video) return captured;
  if (!VIDEOS_ENABLED) {
    const shown = { ...captured };
    delete shown.video;
    return shown;
  }
  return { ...captured, video: { ...captured.video, src: `${VIDEO_BASE_URL}/${id}.mp4` } };
}

/** A video was rendered for this article but isn't being served yet. */
export function videoPending(id: string): boolean {
  return !VIDEOS_ENABLED && Boolean(MEDIA[id]?.video || ("scenario" in (getArticle(id)?.video ?? {})));
}

/** The sidebar tree, small enough to hand to a client component. */
export type NavCategory = {
  id: CategoryId;
  title: string;
  href: string;
  articles: { id: string; title: string; summary: string; href: string }[];
};

export function navTree(): NavCategory[] {
  return CATEGORIES.map((category) => ({
    id: category.id,
    title: category.title,
    href: categoryHref(category.id),
    articles: BY_CATEGORY[category.id].map((article) => ({
      id: article.id,
      title: article.title,
      summary: article.summary,
      href: articleHref(article),
    })),
  }));
}
