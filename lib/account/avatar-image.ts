/**
 * Profile photos: what an upload must be before it's kept and shown to
 * every Noirly app. Only raster formats a browser shows as an image (no SVG,
 * which can carry script), told apart by their bytes rather than by what the
 * upload claims to be, and small enough to serve straight from the database.
 */

export const AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export type AvatarType = (typeof AVATAR_TYPES)[number];

/** The browser shrinks photos to 256×256 before sending; this leaves room for one sent as it is. */
export const MAX_AVATAR_BYTES = 512 * 1024;
export const MAX_AVATAR_SIDE = 1024;
export const MIN_AVATAR_SIDE = 32;
/** What the account page resizes to. */
export const AVATAR_SIZE = 256;

export type ImageInfo = { type: AvatarType; width: number; height: number };

function ascii(bytes: Uint8Array, start: number, length: number) {
  return String.fromCharCode(...bytes.subarray(start, start + length));
}

function png(bytes: Uint8Array): ImageInfo | null {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 24 || signature.some((b, i) => bytes[i] !== b) || ascii(bytes, 12, 4) !== "IHDR") return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { type: "image/png", width: view.getUint32(16), height: view.getUint32(20) };
}

function jpeg(bytes: Uint8Array): ImageInfo | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 2;
  // Walk the segments to the frame header, which holds the size.
  while (offset + 9 < bytes.length) {
    if (bytes[offset] !== 0xff) return null;
    const marker = bytes[offset + 1]!;
    if (marker === 0xff) { offset += 1; continue; }
    const length = view.getUint16(offset + 2);
    const isFrame = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
    if (isFrame) return { type: "image/jpeg", height: view.getUint16(offset + 5), width: view.getUint16(offset + 7) };
    if (length < 2) return null;
    offset += 2 + length;
  }
  return null;
}

function webp(bytes: Uint8Array): ImageInfo | null {
  if (bytes.length < 30 || ascii(bytes, 0, 4) !== "RIFF" || ascii(bytes, 8, 4) !== "WEBP") return null;
  const chunk = ascii(bytes, 12, 4);
  const u24 = (at: number) => bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16);
  if (chunk === "VP8X") return { type: "image/webp", width: u24(24) + 1, height: u24(27) + 1 };
  if (chunk === "VP8 ") {
    if (bytes[23] !== 0x9d || bytes[24] !== 0x01 || bytes[25] !== 0x2a) return null;
    return { type: "image/webp", width: (bytes[26]! | (bytes[27]! << 8)) & 0x3fff, height: (bytes[28]! | (bytes[29]! << 8)) & 0x3fff };
  }
  if (chunk === "VP8L") {
    if (bytes[20] !== 0x2f) return null;
    const bits = bytes[21]! | (bytes[22]! << 8) | (bytes[23]! << 16) | (bytes[24]! << 24);
    return { type: "image/webp", width: (bits & 0x3fff) + 1, height: ((bits >> 14) & 0x3fff) + 1 };
  }
  return null;
}

/** What an image really is, from its first bytes; null if it isn't one we take. */
export function sniffImage(bytes: Uint8Array): ImageInfo | null {
  return png(bytes) ?? jpeg(bytes) ?? webp(bytes);
}

/** Checks an upload is a photo we'll keep: a supported type that matches what was declared, within size. */
export function checkAvatar(bytes: Uint8Array, declaredType: string | null): { ok: true; image: ImageInfo } | { ok: false; error: string } {
  if (bytes.length === 0) return { ok: false, error: "Choose a photo to upload" };
  if (bytes.length > MAX_AVATAR_BYTES) return { ok: false, error: `Photos can be up to ${MAX_AVATAR_BYTES / 1024} KB` };
  const image = sniffImage(bytes);
  if (!image) return { ok: false, error: "Use a PNG, JPEG or WebP photo" };
  const declared = (declaredType ?? "").split(";")[0]!.trim().toLowerCase();
  if (declared !== image.type) return { ok: false, error: "The photo isn't the kind of file it says it is" };
  const { width, height } = image;
  if (width < MIN_AVATAR_SIDE || height < MIN_AVATAR_SIDE) return { ok: false, error: `Photos need to be at least ${MIN_AVATAR_SIDE}×${MIN_AVATAR_SIDE}` };
  if (width > MAX_AVATAR_SIDE || height > MAX_AVATAR_SIDE) return { ok: false, error: `Photos can be up to ${MAX_AVATAR_SIDE}×${MAX_AVATAR_SIDE}` };
  return { ok: true, image };
}
