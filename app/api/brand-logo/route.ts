import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isAllowedBrandLogoUrl, resolveBrandLogoUrl } from "@/lib/brand-logo-url";

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const src = requestUrl.searchParams.get("src")?.trim();
  const absolute = src ? resolveBrandLogoUrl(src, requestUrl.origin) : null;
  if (!absolute || !isAllowedBrandLogoUrl(absolute, requestUrl.origin)) {
    return new Response("URL not allowed", { status: 400 });
  }
  try {
    let text: string;
    const configured = process.env.NEXT_PUBLIC_IDENTITY_LOGO_URL ?? "/brand-mark.svg";
    if (configured === "/brand-mark.svg") {
      text = await readFile(join(process.cwd(), "public", "brand-mark.svg"), "utf8");
    } else {
      const response = await fetch(absolute, { redirect: "error", signal: AbortSignal.timeout(5000), cache: "no-store" });
      if (!response.ok || !response.body) return new Response("Logo unavailable", { status: 502 });
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 256 * 1024) return new Response("Logo too large", { status: 413 });
          chunks.push(value);
        }
      } finally { await reader.cancel(); }
      text = Buffer.concat(chunks).toString("utf8");
    }
    if (!text.includes("<svg")) return new Response("Not an SVG", { status: 415 });
    // SVG is only consumed as an image. A direct navigation cannot run code.
    return new Response(text, { headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; script-src 'none'; sandbox",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "public, max-age=3600",
    } });
  } catch { return new Response("Logo unavailable", { status: 502 }); }
}
