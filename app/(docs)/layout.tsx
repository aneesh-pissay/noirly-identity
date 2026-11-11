import type { ReactNode } from "react";
import { DocsLayout } from "@/components/docs/DocsLayout";
import { MarketingHeader } from "@/components/MarketingHeader";
import { getRequestUser } from "@/lib/auth/request-user";
import { ARTICLES, articleHref, navTree } from "@/lib/docs/registry";
import { buildSearchDocs } from "@/lib/docs/search";

const nav = navTree();
const searchIndex = buildSearchDocs(ARTICLES, articleHref);

/**
 * The Docs are public, linked from the landing page and the account page.
 * They sit under the site header, which offers the account when signed in
 * and sign-in when not. See docs/DOCS-SYSTEM.md.
 */
export default async function DocsRootLayout({ children }: { children: ReactNode }) {
  const user = await getRequestUser().catch(() => null);
  return (
    <div className="flex h-dvh flex-col">
      <MarketingHeader links={[user ? { href: "/account", label: "Account" } : { href: "/login?return_to=/docs", label: "Sign in" }]} />
      <main id="main" className="flex min-h-0 flex-1 flex-col">
        <DocsLayout nav={nav} searchIndex={searchIndex}>{children}</DocsLayout>
      </main>
    </div>
  );
}
