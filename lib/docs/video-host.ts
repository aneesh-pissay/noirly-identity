/**
 * The Docs tutorial MP4s aren't in the repo: they're in Cloudflare R2, served
 * from the bucket's Public Development URL (R2_PUBLIC_URL, e.g.
 * `https://pub-<id>.r2.dev`) as `doc-videos/<article-id>.mp4`.
 * Without it (tests, local setups with no R2), videos are off and articles say
 * a walkthrough is coming.
 */
export function docsVideoBaseUrl(publicUrl = process.env.R2_PUBLIC_URL): string {
  const value = publicUrl?.trim();
  if (!value) return "";
  try {
    return `${new URL(value).origin}/doc-videos`;
  } catch {
    return "";
  }
}
