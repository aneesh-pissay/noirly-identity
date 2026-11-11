import { redirect } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { TextLink } from "@/components/auth-ui";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { getEnv } from "@/lib/config/env";
import { organizationChoices } from "@/lib/oauth/org-context";

/**
 * The organization picker an app gets with `organization=select`: each
 * choice goes back to the same authorization request, naming that
 * organization. Only our own authorization endpoint is a valid way back.
 */
export default async function ChooseOrganizationPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const raw = typeof params.return_to === "string" ? params.return_to : "";
  let back: URL | null = null;
  try {
    const candidate = new URL(raw, getEnv().APP_URL);
    if (candidate.origin === new URL(getEnv().APP_URL).origin && candidate.pathname === "/api/oauth/authorize") back = candidate;
  } catch {
    back = null;
  }
  const user = await getRequestUser();
  if (!user) redirect(`/login?return_to=${encodeURIComponent(back ? back.pathname + back.search : "/account")}`);
  const organizations = await withDb(() => organizationChoices(user.id));
  const linkFor = (id: string) => {
    const url = new URL(back!.toString());
    url.searchParams.set("organization", id);
    return url.pathname + url.search;
  };
  return (
    <AuthShell logo={<AuthLogo />} title="Choose an organization" lead="The app will open in the organization you pick." footer={<TextLink href="/spaces">Manage your spaces</TextLink>}>
      {!back ? (
        <p className="text-sm">This link isn&apos;t complete. Go back to the app and try again.</p>
      ) : organizations.length === 0 ? (
        <p className="text-sm">You&apos;re not in any organization yet. Ask to be invited, or create a space.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-[var(--hairline)] rounded-xl border border-[var(--hairline)]">
          {organizations.map((org) => (
            <li key={org.id}>
              <a className="flex items-center justify-between px-4 py-3 text-sm hover:bg-[var(--surface)]" href={linkFor(org.id)}>
                <span className="font-medium">{org.name}</span>
                <span className="text-xs text-[var(--muted-foreground)]">{org.role}</span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </AuthShell>
  );
}
