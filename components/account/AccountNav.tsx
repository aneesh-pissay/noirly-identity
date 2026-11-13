"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { BookOpen, LogOut, Users, Wrench } from "lucide-react";
import { ACCOUNT_AREAS, type NavItem } from "@/components/account/areas";
import { BusyOverlay } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import { runFrontchannelLogout } from "@/lib/oidc/frontchannel-client";

type Props = {
  user: { displayName: string; email: string; avatarUrl: string | null };
  isAdmin: boolean;
  ownsApps: boolean;
};

const isCurrent = (pathname: string, href: string) => (href === "/account" ? pathname === "/account" : pathname === href || pathname.startsWith(`${href}/`));

function initials(name: string) {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]!.toUpperCase()).join("") || "?";
}

function SignOutButton({ className }: { className?: string }) {
  const [busy, setBusy] = useState(false);
  async function signOut() {
    setBusy(true);
    try {
      const response = await fetch("/api/auth/logout", { method: "POST", credentials: "include", headers: { "x-csrf-token": await getCsrf() } });
      // Apps Identity couldn't reach directly sign out in hidden frames first.
      const data = (await response.json().catch(() => ({}))) as { frontchannelLogoutUrls?: string[] };
      await runFrontchannelLogout(data.frontchannelLogoutUrls);
    } finally {
      window.location.assign(new URL("/login", window.location.origin).toString());
    }
  }
  return (
    <>
      {busy ? <BusyOverlay label="Signing out" /> : null}
      <button type="button" onClick={() => void signOut()} className={className}>
        <LogOut size={16} aria-hidden /> Sign out
      </button>
    </>
  );
}

const linkClass = (active: boolean) =>
  [
    "flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition-colors",
    active ? "bg-[var(--surface-2)] font-medium text-[var(--foreground)]" : "text-[var(--muted-foreground)] hover:bg-[var(--surface-2)] hover:text-[var(--foreground)]",
  ].join(" ");

/**
 * The account sidebar: who's signed in, the six areas, then spaces, admin
 * tools and sign out. Below `md` it's a row of tabs that scrolls sideways,
 * and the home page lists the same areas as cards.
 */
export function AccountNav({ user, isAdmin, ownsApps }: Props) {
  const pathname = usePathname();
  const extras: NavItem[] = [
    { href: "/spaces", label: "Spaces", icon: Users },
    ...(isAdmin || ownsApps ? [{ href: "/clients", label: isAdmin ? "Apps and APIs" : "Your apps", icon: Wrench }] : []),
    { href: "/docs", label: "Help and docs", icon: BookOpen },
  ];

  return (
    <>
      <nav aria-label="Account" className="sticky top-0 z-10 -mx-4 mb-6 overflow-x-auto border-b border-[var(--hairline)] bg-[var(--bg)]/90 px-4 py-2 backdrop-blur md:hidden">
        <ul className="flex gap-1">
          {ACCOUNT_AREAS.map((item) => {
            const active = isCurrent(pathname, item.href);
            return (
              <li key={item.href} className="shrink-0">
                <Link href={item.href} aria-current={active ? "page" : undefined}
                  className={`block rounded-full px-3 py-1.5 text-sm ${active ? "bg-[var(--surface-2)] font-medium text-[var(--foreground)]" : "text-[var(--muted-foreground)]"}`}>
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <aside className="hidden w-64 shrink-0 md:block">
        <div className="sticky top-8 flex flex-col gap-6">
          <div className="flex items-center gap-3 px-3">
            {user.avatarUrl ? (
              // eslint-disable-next-line @next/next/no-img-element -- served by Identity with its own caching
              <img src={user.avatarUrl} alt="" width={40} height={40} className="size-10 rounded-full object-cover" />
            ) : (
              <span aria-hidden className="flex size-10 items-center justify-center rounded-full bg-[var(--surface-2)] text-sm font-medium">{initials(user.displayName)}</span>
            )}
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user.displayName}</p>
              <p className="truncate text-xs text-[var(--muted-foreground)]">{user.email}</p>
            </div>
          </div>

          <nav aria-label="Account">
            <ul className="flex flex-col gap-1">
              {ACCOUNT_AREAS.map((item) => {
                const active = isCurrent(pathname, item.href);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link href={item.href} aria-current={active ? "page" : undefined} className={linkClass(active)}>
                      <Icon size={16} aria-hidden /> {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>

          <div className="border-t border-[var(--hairline)] pt-4">
            <ul className="flex flex-col gap-1">
              {extras.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link href={item.href} className={linkClass(false)}>
                      <Icon size={16} aria-hidden /> {item.label}
                    </Link>
                  </li>
                );
              })}
              <li>
                <SignOutButton className={`${linkClass(false)} w-full`} />
              </li>
            </ul>
          </div>
        </div>
      </aside>
    </>
  );
}

/** Sign out, for small screens where the sidebar isn't shown (the Account page has it). */
export function MobileSignOut() {
  return <SignOutButton className="inline-flex items-center gap-2 rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm" />;
}
