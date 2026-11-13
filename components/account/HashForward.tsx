"use client";

import { useEffect } from "react";

/**
 * Old links to a section of the one long account page (`/account#security-title`,
 * from emails already sent) go on to the page that has that section now.
 */
const PAGE_OF: Record<string, string> = {
  "security-title": "/account/security",
  "sign-in-methods": "/account/security",
  "methods-title": "/account/security",
  password: "/account/security",
  "recovery-methods-title": "/account/security",
  "emails-title": "/account/profile",
  "phone-title": "/account/profile",
  "prefs-title": "/account/profile",
  "devices-title": "/account/devices",
  "lifetime-title": "/account/devices",
  "activity-title": "/account/devices",
  "apps-title": "/account/privacy",
  "merge-title": "/account/manage",
  "freeze-title": "/account/manage",
};

export function HashForward() {
  useEffect(() => {
    const id = window.location.hash.slice(1);
    const page = PAGE_OF[id];
    // A plain redirect: only old links land here, and the browser then scrolls to the section itself.
    if (page) window.location.replace(`${page}#${id}`);
  }, []);
  return null;
}
