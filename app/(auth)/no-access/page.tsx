import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { TextLink } from "@/components/auth-ui";
import { withDb } from "@/lib/api/with-db";
import { appDisplayName } from "@/lib/oauth/environments";
import { environmentOf } from "@/lib/oauth/client-admin";
import { OAuthClient } from "@/models/OAuthClient";

/**
 * Shown instead of signing someone in to an app whose access policy doesn't
 * include them (lib/oauth/access-policy.ts). The app is named from Identity's
 * own records, never from text in the address.
 */
export default async function NoAccessPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const clientId = typeof params.client_id === "string" ? params.client_id.slice(0, 200) : "";
  const client = clientId ? await withDb(() => OAuthClient.findOne({ clientId }).select("name environment redirectUris").lean()) : null;
  const name = client ? appDisplayName(client.name, environmentOf(client)) : "this app";
  return (
    <AuthShell
      logo={<AuthLogo />}
      title="No access"
      lead={`Your Noirly account doesn't have access to ${name}.`}
      footer={<TextLink href="/account">Go to your account</TextLink>}
    >
      <div className="flex flex-col gap-4 text-sm">
        <p>Whoever runs {name} decides who can use it. Ask them to add you, or sign in with an account that has access.</p>
        <TextLink href="/login?prompt=select_account">Use a different account</TextLink>
      </div>
    </AuthShell>
  );
}
