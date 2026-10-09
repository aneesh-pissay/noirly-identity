import Link from "next/link";
import { Button, Card, CardContent, CardHeader, CardTitle } from "@noirly-dev/ui";
import { BrandMark } from "@/components/BrandMark";
import { SiteFooter } from "@/components/LegalPage";
import { MarketingHeader } from "@/components/MarketingHeader";

const features = [
  {
    title: "One account",
    copy: "Sign in once and carry the same identity across Flow, Ledger, Pulse, and every Noirly app.",
  },
  {
    title: "Email & Google",
    copy: "Password login, Google, and One Tap — verification handled in the same place.",
  },
  {
    title: "OpenID Connect",
    copy: "Standards-based OAuth and OIDC for every product client, with PKCE and consent.",
  },
  {
    title: "Secure by default",
    copy: "CSRF protection, hashed passwords, and short-lived tokens for every session.",
  },
  {
    title: "Account control",
    copy: "Update your profile and password in one place. Admins can register OAuth apps.",
  },
  {
    title: "Popup-ready",
    copy: "Product apps open Identity in a secure popup and return when you are signed in.",
  },
];

export default function Home() {
  return (
    <div className="flex min-h-dvh flex-1 flex-col">
      <MarketingHeader />

      <main id="main" className="flex flex-1 flex-col">
        <section className="shell section-y">
          <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
            <BrandMark className="size-[4.25rem] md:size-20" />
            <p className="eyebrow mt-7">Authentication &amp; SSO</p>
            <h1 className="display-lg mt-4 text-balance">
              One identity for the whole Noirly ecosystem.
            </h1>
            <p className="lede mt-5 text-center">
              Central sign-in, verification, and OpenID Connect for every Noirly
              product — without a new password for each app.
            </p>

            <div className="mt-9 flex w-full max-w-xs flex-col gap-3">
              <Button asChild size="lg" className="w-full">
                <Link href="/login">Sign in</Link>
              </Button>
              <Button asChild size="lg" variant="secondary" className="w-full">
                <Link href="/register">Create account</Link>
              </Button>
            </div>
          </div>
        </section>

        <section className="section-rule relative">
          <div className="shell section-y">
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow justify-center">What it covers</p>
              <h2 className="display-md mt-4">Built for every Noirly product</h2>
            </div>

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
          <span className="meta">Auth · OIDC · PKCE</span>
        </div>
      </footer>
      <SiteFooter />
    </div>
  );
}
