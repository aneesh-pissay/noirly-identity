"use client";

import Link from "next/link";
import { BrandMark } from "@/components/BrandMark";
import { ThemeControls } from "@/components/ThemeControls";

const BRAND_NAME = "Noirly Identity";

/** `links` sit before the theme controls (the landing page links the Docs; the Docs link sign-in or the account). */
export function MarketingHeader({ links = [] }: { links?: { href: string; label: string }[] }) {
  return (
    <header className="sticky top-0 z-20 border-b border-[var(--hairline)] bg-[var(--bg)]/70 backdrop-blur-xl">
      <div className="shell flex h-[4.5rem] items-center justify-between gap-4 md:h-20">
        <Link
          href="/"
          aria-label={`${BRAND_NAME} home`}
          className="focusable group flex min-w-0 shrink-0 items-center gap-2.5 rounded-[var(--r-sm)] text-[var(--text)]"
        >
          <span className="inline-flex size-[4.25rem] shrink-0 sm:hidden" aria-hidden>
            <BrandMark className="size-full" />
          </span>
          <span className="hidden items-center gap-3 font-display text-xl font-bold leading-none tracking-[-0.04em] uppercase sm:flex md:text-2xl lg:text-3xl">
            <span className="inline-flex size-14 shrink-0 md:size-16" aria-hidden>
              <BrandMark className="size-full" />
            </span>
            <span className="truncate">{BRAND_NAME}</span>
          </span>
        </Link>
        <div className="flex items-center gap-3 sm:gap-5">
          {links.map((link) => (
            <Link key={link.href} href={link.href} className="focusable rounded-[var(--r-sm)] text-sm text-[var(--muted-foreground)] hover:text-[var(--foreground)]">
              {link.label}
            </Link>
          ))}
          <ThemeControls />
        </div>
      </div>
    </header>
  );
}
