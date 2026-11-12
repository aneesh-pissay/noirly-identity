import Link from "next/link";
import type { Metadata } from "next";
import { Button, Card, CardContent, CardHeader, CardTitle } from "@noirly-dev/ui";
import { BrandMark } from "@/components/BrandMark";
import { SiteFooter } from "@/components/LegalPage";
import { MarketingHeader } from "@/components/MarketingHeader";
import { ARTICLES, CATEGORIES } from "@/lib/docs/registry";

export const metadata: Metadata = {
  title: "Noirly Identity",
  description:
    "One sign-in for every Noirly app: passkeys, two-step verification, spaces for teams, and single sign-on and provisioning for organizations.",
};

type Feature = { title: string; copy: string };

const groups: Array<{ id: string; eyebrow: string; title: string; lede: string; features: Feature[] }> = [
  {
    id: "you",
    eyebrow: "For you",
    title: "Sign in your way, and stay in control",
    lede: "One account for Flow, Ledger and every other Noirly app, protected from the first sign-in.",
    features: [
      { title: "Passkeys and more", copy: "Sign in with a passkey, a password, Google, Apple, Microsoft or GitHub, or a link sent by email. Keep more than one, so a lost phone isn't a lockout." },
      { title: "Two-step verification", copy: "An authenticator app, passkeys or security keys, with recovery codes. Risky sign-ins are asked for more proof even if you haven't set one up." },
      { title: "Alerts and a freeze button", copy: "An email for every new device and every change to how you sign in, with a link that freezes the account at once if it wasn't you." },
      { title: "Devices, history and apps", copy: "See every signed-in device, every sign-in and change, and every app that can see your details. Sign any of them out in a click." },
      { title: "Your data, your call", copy: "A privacy page that says what's kept and why, one download with your data from every Noirly app, and closing with a 14-day undo." },
      { title: "Safe recovery", copy: "Lost your second step? Get back in after a visible, cancellable wait, so someone with only your password can't." },
    ],
  },
  {
    id: "teams",
    eyebrow: "For teams and organizations",
    title: "One team across every app",
    lede: "Spaces carry your people, roles and rules into every Noirly app, and connect to the directory you already run.",
    features: [
      { title: "Spaces", copy: "A household, a club or a company: members, roles, teams and invitations in one place. Apps that link to a space follow it." },
      { title: "Single sign-on", copy: "Microsoft Entra ID, Okta, or any OpenID Connect or SAML provider. Require it for your domains, with audited break-glass access." },
      { title: "Directory provisioning", copy: "SCIM 2.0 creates, updates and deactivates people as your directory changes. Deactivation signs them out of every app at once." },
      { title: "Security rules", copy: "Require a second step, choose which sign-in methods count, and cap session lengths for everyone in the space." },
      { title: "Roles and permissions", copy: "Define roles once and let every app ask who may do what. Nothing is allowed unless a role grants it; access can be asked for and time-limited." },
      { title: "Bulk tools", copy: "Invite hundreds at once or import a CSV, verify your domains, and spot duplicate accounts before they cause trouble." },
    ],
  },
  {
    id: "developers",
    eyebrow: "For developers and admins",
    title: "Standards, logs and evidence",
    lede: "Built on OpenID Connect, with the audit trail and controls a security review asks for.",
    features: [
      { title: "OpenID Connect", copy: "Authorization code with PKCE, consent, refresh tokens, resource indicators for your APIs and client credentials for services." },
      { title: "Logout and lifecycle events", copy: "Back-channel logout, signed account-deleted notices and lifecycle webhooks, retried until each app answers." },
      { title: "Tamper-evident audit log", copy: "Every sign-in, change and admin action in hash-chained streams, with search, export, alert rules and retention." },
      { title: "Compliance evidence", copy: "Policies, a controls list and live evidence for a review: chain integrity, key age, second-step coverage and more." },
    ],
  },
];

function FeatureGrid({ features }: { features: Feature[] }) {
  return (
    <div className="mt-12 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
      {features.map((item) => (
        <Card key={item.title} variant="interactive">
          <CardHeader>
            <CardTitle>{item.title}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="copy">{item.copy}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default function Home() {
  return (
    <div className="flex min-h-dvh flex-1 flex-col">
      <MarketingHeader links={[{ href: "/docs", label: "Docs" }]} />

      <main id="main" className="flex flex-1 flex-col">
        <section className="shell section-y">
          <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
            <BrandMark className="size-[4.25rem] md:size-20" />
            <p className="eyebrow mt-7">Accounts &amp; single sign-on</p>
            <h1 className="display-lg mt-4 text-balance">One sign-in for every Noirly app.</h1>
            <p className="lede mt-5 text-center">
              Passkeys and two-step verification for you; spaces, single sign-on and provisioning for your team. No new
              password for each app.
            </p>

            <div className="mt-9 flex w-full max-w-xs flex-col gap-3">
              <Button asChild size="lg" className="w-full">
                <Link href="/login">Sign in</Link>
              </Button>
              <Button asChild size="lg" variant="secondary" className="w-full">
                <Link href="/register">Create account</Link>
              </Button>
            </div>
            <p className="meta mt-4">
              One account for Flow, Ledger and more ·{" "}
              <Link href="/docs" className="underline-offset-4 hover:text-[var(--text)] hover:underline">
                Read the docs
              </Link>
            </p>
          </div>
        </section>

        {groups.map((group) => (
          <section key={group.id} aria-labelledby={`${group.id}-title`} className="section-rule relative">
            <div className="shell section-y">
              <div className="mx-auto max-w-2xl text-center">
                <p className="eyebrow justify-center">{group.eyebrow}</p>
                <h2 id={`${group.id}-title`} className="display-md mt-4">{group.title}</h2>
                <p className="lede mt-5 text-center">{group.lede}</p>
              </div>
              <FeatureGrid features={group.features} />
            </div>
          </section>
        ))}

        <section aria-labelledby="docs-title" className="section-rule relative">
          <div className="shell section-y">
            <div className="mx-auto flex max-w-2xl flex-col items-center text-center">
              <p className="eyebrow justify-center">Docs</p>
              <h2 id="docs-title" className="display-md mt-4">Every feature, explained</h2>
              <p className="lede mt-5 text-center">
                {ARTICLES.length} guides across {CATEGORIES.length} topics, from your first sign-in to connecting Entra ID.
                Read them before you sign up.
              </p>
              <Link
                href="/docs"
                className="focusable mt-8 inline-flex min-h-11 items-center rounded-full border border-[var(--hairline)] px-5 text-sm font-medium text-[var(--text)] hover:bg-[var(--surface-2)]"
              >
                Browse the docs
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="section-rule relative">
        <div className="shell flex flex-wrap items-center justify-between gap-4 py-7">
          <span className="flex items-center gap-4 text-[var(--text)]">
            <span className="inline-flex size-[4.25rem] shrink-0 md:size-20">
              <BrandMark className="size-full" />
            </span>
            <span className="display-md">Noirly Identity</span>
          </span>
          <span className="flex flex-wrap items-center gap-4">
            <span className="meta">Passkeys · SSO · SCIM · OIDC</span>
            <Link href="/docs" className="meta underline-offset-4 hover:text-[var(--text)] hover:underline">
              Docs
            </Link>
          </span>
        </div>
      </footer>
      <SiteFooter />
    </div>
  );
}
