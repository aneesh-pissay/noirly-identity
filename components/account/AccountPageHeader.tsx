import type { ReactNode } from "react";

/** The title and one-line explanation at the top of each account page. */
export function AccountPageHeader({ title, lead, children }: { title: string; lead: string; children?: ReactNode }) {
  return (
    <header className="mb-8 pr-24">
      <h1 className="font-display text-3xl font-semibold tracking-tight md:text-4xl">{title}</h1>
      <p className="mt-2 max-w-2xl text-[var(--muted-foreground)]">{lead}</p>
      {children}
    </header>
  );
}

/**
 * The sections on an account page, one under another. The shared section
 * components carry their own outer margins for the old single page; here the
 * column sets the spacing instead.
 */
export function AccountSections({ children }: { children: ReactNode }) {
  return <div className="flex flex-col gap-6 [&>section]:mx-0 [&>section]:my-0 [&>section]:max-w-none">{children}</div>;
}
