/**
 * A device id: a random value in a long-lived cookie for browsers, or the
 * `X-Noirly-Device` header a native app sends. It isn't proof of anything (a
 * client can drop or change it); it's a signal, used for rate limits that
 * span accounts and for noticing a sign-in from a device never seen before.
 */
export const DEVICE_COOKIE = "noirly_device";
const DEVICE_ID = /^[A-Za-z0-9_-]{16,64}$/;

export function deviceIdFrom(request: Request): string | null {
  const header = request.headers.get("x-noirly-device");
  if (header && DEVICE_ID.test(header)) return header;
  const cookie = request.headers.get("cookie") ?? "";
  const match = cookie.split(/;\s*/).find((part) => part.startsWith(`${DEVICE_COOKIE}=`));
  const value = match?.slice(DEVICE_COOKIE.length + 1) ?? null;
  return value && DEVICE_ID.test(value) ? value : null;
}
