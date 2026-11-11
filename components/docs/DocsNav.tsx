"use client";

import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { ChevronRight, Search } from "lucide-react";
import type { NavCategory } from "@/lib/docs/registry";
import { searchDocs, snippet, type SearchDoc } from "@/lib/docs/search";

const OPEN_KEY = "identity-docs-open-groups";

function readOpen(): string[] {
  try {
    const value = JSON.parse(localStorage.getItem(OPEN_KEY) ?? "[]");
    return Array.isArray(value) ? value.filter((v) => typeof v === "string") : [];
  } catch {
    return [];
  }
}

function linkClass(active: boolean) {
  return [
    "block rounded-lg px-2.5 py-1.5 text-sm leading-snug transition-colors",
    active
      ? "bg-[var(--accent-soft)] text-[var(--accent)]"
      : "text-[var(--muted-foreground)] hover:bg-[var(--surface-2)] hover:text-[var(--foreground)]",
  ].join(" ");
}

/**
 * Docs sidebar: search, then the categories as collapsible groups. The group
 * holding the current page is always open; the others remember whether you
 * opened them. Arrow keys move between visible links; "/" focuses search.
 */
export function DocsNav({ nav, searchIndex, autoFocusSearch = false }: { nav: NavCategory[]; searchIndex: SearchDoc[]; autoFocusSearch?: boolean }) {
  const pathname = usePathname();
  const router = useRouter();
  const listId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const treeRef = useRef<HTMLElement>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [open, setOpen] = useState<string[]>([]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- saved groups load after mount; the server render can't know them
    setOpen(readOpen());
  }, []);

  useEffect(() => {
    if (autoFocusSearch) inputRef.current?.focus();
  }, [autoFocusSearch]);

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results = useMemo(() => searchDocs(searchIndex, query, 12), [searchIndex, query]);
  const currentCategory = nav.find((category) => pathname === category.href || pathname.startsWith(`${category.href}/`))?.id;

  const toggle = (id: string) => {
    setOpen((previous) => {
      const next = previous.includes(id) ? previous.filter((value) => value !== id) : [...previous, id];
      try { localStorage.setItem(OPEN_KEY, JSON.stringify(next)); } catch { /* storage may be unavailable */ }
      return next;
    });
  };

  const go = (href: string) => {
    setQuery("");
    router.push(href);
  };

  const onSearchKey = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" && results.length) {
      event.preventDefault();
      setActive((index) => (index + 1) % results.length);
    } else if (event.key === "ArrowUp" && results.length) {
      event.preventDefault();
      setActive((index) => (index - 1 + results.length) % results.length);
    } else if (event.key === "Enter" && results[active]) {
      event.preventDefault();
      go(results[active].href);
    } else if (event.key === "Escape") {
      setQuery("");
    }
  };

  // Up/Down between the tree's visible links and group buttons.
  const onTreeKey = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const items = Array.from(treeRef.current?.querySelectorAll<HTMLElement>("[data-nav-item]") ?? []);
    const at = items.indexOf(document.activeElement as HTMLElement);
    if (at < 0) return;
    event.preventDefault();
    items[(at + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus();
  };

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link href="/docs" className="font-display text-base font-semibold tracking-tight text-[var(--foreground)]">
          Identity Docs
        </Link>
        <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">Every feature, explained and shown.</p>
      </div>

      <div className="relative">
        <label htmlFor={`${listId}-search`} className="sr-only">Search the docs</label>
        <Search size={14} aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted-foreground)]" />
        <input
          ref={inputRef}
          id={`${listId}-search`}
          type="search"
          role="combobox"
          aria-expanded={Boolean(query && results.length)}
          aria-controls={`${listId}-results`}
          aria-activedescendant={results[active] ? `${listId}-r${active}` : undefined}
          aria-autocomplete="list"
          value={query}
          onChange={(event) => { setQuery(event.target.value); setActive(0); }}
          onKeyDown={onSearchKey}
          placeholder="Search docs… (/)"
          className="h-10 w-full rounded-xl border border-[var(--hairline)] bg-[var(--surface-2)] pl-9 pr-3 text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
        />
      </div>

      {query.trim() ? (
        <div>
          {results.length ? (
            <ul id={`${listId}-results`} role="listbox" aria-label="Search results" className="flex flex-col gap-1">
              {results.map((result, index) => (
                <li key={`${result.href}-${index}`} id={`${listId}-r${index}`} role="option" aria-selected={index === active}>
                  <Link href={result.href} onClick={() => setQuery("")} onMouseEnter={() => setActive(index)}
                    className={`block rounded-lg px-2.5 py-2 text-sm ${index === active ? "bg-[var(--surface-2)]" : ""}`}>
                    <span className="block font-medium text-[var(--foreground)]">{result.title}</span>
                    <span className="block font-mono text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                      {result.section === "Article" ? "Article" : `${result.section} · ${result.article}`}
                    </span>
                    <span className="mt-0.5 block text-xs leading-snug text-[var(--muted-foreground)]">{snippet(result.text, query)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p role="status" className="px-1 text-sm text-[var(--muted-foreground)]">No results for “{query.trim()}”.</p>
          )}
        </div>
      ) : (
        <nav ref={treeRef} aria-label="Docs sections" onKeyDown={onTreeKey}>
          <ul className="flex flex-col gap-1">
            {nav.map((category) => {
              const expanded = category.id === currentCategory || open.includes(category.id);
              const groupId = `${listId}-${category.id}`;
              return (
                <li key={category.id}>
                  <div className="flex items-center gap-1">
                    <button type="button" data-nav-item onClick={() => toggle(category.id)} aria-expanded={expanded} aria-controls={groupId}
                      aria-label={`${expanded ? "Collapse" : "Expand"} ${category.title}`}
                      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-[var(--muted-foreground)] hover:bg-[var(--surface-2)]">
                      <ChevronRight size={14} aria-hidden className={`transition-transform ${expanded ? "rotate-90" : ""}`} />
                    </button>
                    <Link href={category.href} data-nav-item aria-current={pathname === category.href ? "page" : undefined}
                      className={`flex-1 rounded-md px-1.5 py-1 font-mono text-[11px] uppercase tracking-[0.14em] ${pathname === category.href ? "text-[var(--accent)]" : "text-[var(--muted-foreground)] hover:text-[var(--foreground)]"}`}>
                      {category.title}
                    </Link>
                  </div>
                  <ul id={groupId} hidden={!expanded} className="mb-2 ml-3.5 mt-1 flex flex-col gap-0.5 border-l border-[var(--hairline)] pl-2.5">
                    {category.articles.map((article) => {
                      const current = pathname === article.href;
                      return (
                        <li key={article.id}>
                          <Link href={article.href} data-nav-item title={article.summary} aria-current={current ? "page" : undefined} className={linkClass(current)}>
                            {article.title}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </li>
              );
            })}
          </ul>
        </nav>
      )}
    </div>
  );
}
