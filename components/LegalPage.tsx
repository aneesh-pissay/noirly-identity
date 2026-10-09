import Link from "next/link";
import type { ReactNode } from "react";
import { MarketingHeader } from "@/components/MarketingHeader";

/** Long-form page frame (privacy policy, account deletion): header, readable column, footer links. */
export function LegalPage({
  eyebrow,
  title,
  lead,
  children,
}: {
  eyebrow: string;
  title: string;
  lead?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex min-h-dvh flex-1 flex-col">
      <MarketingHeader />
      <main id="main" className="flex flex-1 flex-col">
        <article className="shell section-y">
          <div className="mx-auto flex max-w-3xl flex-col">
            <p className="eyebrow">{eyebrow}</p>
            <h1 className="display-md mt-4 text-balance">{title}</h1>
            {lead ? <div className="lede mt-5">{lead}</div> : null}
            <div className="legal mt-10 flex flex-col gap-10">{children}</div>
          </div>
        </article>
      </main>
      <SiteFooter />
    </div>
  );
}

export function LegalSection({ id, title, children }: { id?: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className="flex scroll-mt-28 flex-col gap-3">
      <h2 id={id ? `${id}-title` : undefined} className="font-display text-xl font-semibold tracking-tight text-[var(--text)]">
        {title}
      </h2>
      <div className="copy flex flex-col gap-3 [&_a]:underline [&_a]:underline-offset-4 [&_li]:ml-5 [&_li]:list-disc [&_strong]:text-[var(--text)] [&_ul]:flex [&_ul]:flex-col [&_ul]:gap-1.5">
        {children}
      </div>
    </section>
  );
}

export function SiteFooter() {
  return (
    <footer className="section-rule relative">
      <nav aria-label="Legal" className="shell flex flex-wrap items-center gap-x-6 gap-y-2 py-6 text-sm text-[var(--muted-foreground)]">
        <span>© {new Date().getFullYear()} Noirly</span>
        <Link href="/privacy" className="underline-offset-4 hover:text-[var(--foreground)] hover:underline">
          Privacy policy
        </Link>
        <Link href="/delete-account" className="underline-offset-4 hover:text-[var(--foreground)] hover:underline">
          Delete your account
        </Link>
        <Link href="/login" className="underline-offset-4 hover:text-[var(--foreground)] hover:underline">
          Sign in
        </Link>
      </nav>
    </footer>
  );
}
