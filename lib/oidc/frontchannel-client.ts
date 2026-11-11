"use client";

const FRAME_TIMEOUT_MS = 3000;

/**
 * Front-channel logout: loads each app's logout URL in a hidden frame so the
 * app can clear its own cookies, then resolves once they've all loaded or
 * a few seconds have passed, whichever is first. Only pages whose policy
 * allows framing apps (lib/security/request.ts) can use it.
 */
export function runFrontchannelLogout(urls: readonly string[] | undefined): Promise<void> {
  if (!urls?.length || typeof document === "undefined") return Promise.resolve();
  const frames = urls.map((url) => {
    const frame = document.createElement("iframe");
    frame.hidden = true;
    frame.title = "Signing out of an app";
    frame.setAttribute("aria-hidden", "true");
    frame.referrerPolicy = "no-referrer";
    frame.src = url;
    return frame;
  });
  const loaded = frames.map((frame) => new Promise<void>((resolve) => {
    frame.addEventListener("load", () => resolve(), { once: true });
    frame.addEventListener("error", () => resolve(), { once: true });
  }));
  for (const frame of frames) document.body.appendChild(frame);
  return Promise.race([
    Promise.all(loaded).then(() => undefined),
    new Promise<void>((resolve) => window.setTimeout(resolve, FRAME_TIMEOUT_MS)),
  ]);
}
