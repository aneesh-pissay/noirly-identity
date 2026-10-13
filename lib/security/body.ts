import { AppError } from "@/lib/api/errors";
/** Bounded parsing; JSON endpoints never accept multipart uploads. */
export async function readLimitedText(request: Request, maxBytes = 256 * 1024): Promise<string> {
  const size = Number(request.headers.get("content-length"));
  if (Number.isFinite(size) && size > maxBytes) throw new AppError("Request body is too large", 413, "payload_too_large");
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new AppError("Request body is too large", 413, "payload_too_large");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString("utf8");
}
