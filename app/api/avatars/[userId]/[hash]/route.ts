import { withDb } from "@/lib/api/with-db";
import { readAvatar } from "@/lib/account/avatar";

/**
 * Serves a profile photo to any app or page that shows it. The address
 * holds the photo's hash, so it never changes under a cache: a new photo
 * gets a new address, and an old address stops working.
 */
export async function GET(_request: Request, context: { params: Promise<{ userId: string; hash: string }> }) {
  const { userId, hash } = await context.params;
  const avatar = await withDb(() => readAvatar(userId, hash));
  if (!avatar) return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  return new Response(avatar.bytes, {
    headers: {
      "Content-Type": avatar.contentType,
      "Cache-Control": "public, max-age=31536000, immutable",
      "X-Content-Type-Options": "nosniff",
      // An image and nothing else, even if opened directly.
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Content-Disposition": "inline",
      // Shown on other Noirly origins.
      "Cross-Origin-Resource-Policy": "cross-origin",
    },
  });
}
