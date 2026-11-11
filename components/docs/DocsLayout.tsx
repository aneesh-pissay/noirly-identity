"use client";

import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { usePathname } from "next/navigation";
import { BookOpen, X } from "lucide-react";
import type { NavCategory } from "@/lib/docs/registry";
import type { SearchDoc } from "@/lib/docs/search";
import { DocsNav } from "@/components/docs/DocsNav";

/**
 * The Docs frame: the docs sidebar beside a scrolling content pane, laid out
 * like the workspace shell (each pane scrolls on its own). Below `lg` the
 * sidebar becomes a drawer opened from the bar above the content.
 */
export function DocsLayout({ nav, searchIndex, children }: { nav: NavCategory[]; searchIndex: SearchDoc[]; children: ReactNode }) {
  const pathname = usePathname();
  const [drawer, setDrawer] = useState(false);
  const [drawerPath, setDrawerPath] = useState(pathname);
  // Navigating from the drawer closes it.
  if (drawerPath !== pathname) {
    setDrawerPath(pathname);
    setDrawer(false);
  }

  useEffect(() => {
    if (!drawer) return;
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setDrawer(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawer]);

  return (
    // Lenis smooth-scrolls only the document and swallows wheel events over the
    // panes below, which scroll on their own; opt out here (also outside the app shell).
    <div data-lenis-prevent className="flex h-full min-h-0 flex-1 flex-col lg:flex-row">
      <aside aria-label="Documentation" className="hidden shrink-0 border-r border-[var(--hairline)] bg-[var(--surface-2)]/40 lg:block lg:w-72">
        <div className="h-full overflow-y-auto px-4 py-5">
          <DocsNav nav={nav} searchIndex={searchIndex} />
        </div>
      </aside>

      <div className="flex items-center gap-2 border-b border-[var(--hairline)] px-4 py-2.5 sm:px-6 lg:hidden">
        <button type="button" onClick={() => setDrawer(true)} aria-expanded={drawer} aria-controls="docs-drawer"
          className="flex min-h-10 items-center gap-2 rounded-xl border border-[var(--hairline)] bg-[var(--surface-2)] px-3 text-sm text-[var(--foreground)]">
          <BookOpen size={15} aria-hidden />
          Browse docs
        </button>
      </div>

      {/* On body, so the app header can't cover the drawer (the content pane is its own stacking context). */}
      {drawer ? createPortal(
        <div data-lenis-prevent className="fixed inset-0 z-50 lg:hidden">
          <button type="button" aria-label="Close docs menu" onClick={() => setDrawer(false)} className="absolute inset-0 bg-black/50" />
          <div id="docs-drawer" role="dialog" aria-modal="true" aria-label="Documentation"
            className="absolute inset-y-0 left-0 flex w-[min(20rem,88vw)] flex-col border-r border-[var(--hairline)] bg-[var(--bg)] shadow-xl">
            <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-3">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--muted-foreground)]">Docs</p>
              <button type="button" onClick={() => setDrawer(false)} aria-label="Close docs menu"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-[var(--muted-foreground)] hover:bg-[var(--surface-2)]">
                <X size={16} aria-hidden />
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
              <DocsNav nav={nav} searchIndex={searchIndex} autoFocusSearch />
            </div>
          </div>
        </div>,
        document.body,
      ) : null}

      <div id="docs-main" className="min-h-0 min-w-0 flex-1 overflow-y-auto scroll-smooth">{children}</div>
    </div>
  );
}
