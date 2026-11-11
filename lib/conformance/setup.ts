import { generateSecureToken } from "@/lib/security/crypto";
import { hashPassword } from "@/lib/security/password";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";

/**
 * Sets Identity up for the OpenID Foundation conformance suite
 * (docs/CONFORMANCE.md): two confidential clients registered at the suite's
 * callback addresses for one test alias, and a test account to sign in with.
 * Secrets and the password are fresh each run and only ever returned, for the
 * suite's config file. `removeConformanceSetup` takes it all away again.
 */

export const CONFORMANCE_CLIENT_IDS = ["conformance-1", "conformance-2"] as const;
export const CONFORMANCE_EMAIL = "conformance@noirly.test";

export type ConformanceSetup = {
  /** The suite's config for the oidcc test plans (static client, discovery). */
  suiteConfig: {
    alias: string;
    description: string;
    server: { discoveryUrl: string };
    client: { client_id: string; client_secret: string };
    client2: { client_id: string; client_secret: string };
    browser: unknown[];
  };
  /** Who to sign in as when the suite sends you to Identity. */
  account: { email: string; password: string };
};

export async function createConformanceSetup(input: { issuer: string; suiteUrl: string; alias: string }): Promise<ConformanceSetup> {
  const issuer = input.issuer.replace(/\/$/, "");
  const suite = input.suiteUrl.replace(/\/$/, "");
  if (!/^[a-z0-9-]{1,40}$/.test(input.alias)) throw new Error("alias: lowercase letters, numbers and hyphens");
  const base = `${suite}/test/a/${input.alias}`;

  const clients = [];
  for (const clientId of CONFORMANCE_CLIENT_IDS) {
    const secret = generateSecureToken(32);
    await OAuthClient.findOneAndDelete({ clientId });
    await OAuthClient.create({
      clientId,
      clientSecretHash: await hashPassword(secret),
      name: `Conformance suite (${clientId})`,
      description: `OpenID conformance suite client for alias ${input.alias}`,
      redirectUris: [`${base}/callback`],
      postLogoutRedirectUris: [`${base}/post_logout_redirect`],
      allowedScopes: ["openid", "profile", "email", "offline_access"],
      clientType: "confidential",
      status: "active",
      // The suite's basic plans don't send PKCE; a confidential client may go without.
      requirePkce: false,
      requireConsent: false,
      backchannelLogoutUri: `${base}/backchannel_logout`,
      frontchannelLogoutUri: `${base}/frontchannel_logout`,
    });
    clients.push({ client_id: clientId, client_secret: secret });
  }

  const password = `${generateSecureToken(18)}aA1!`;
  await User.findOneAndUpdate(
    { email: CONFORMANCE_EMAIL },
    {
      $set: {
        passwordHash: await hashPassword(password),
        emailVerified: true,
        status: "active",
        mfaRequired: false,
        // Claims the suite looks for under the profile scope.
        locale: "en-GB",
        zoneinfo: "Europe/London",
      },
      $setOnInsert: { firstName: "Conformance", lastName: "Tester", displayName: "Conformance Tester", roles: ["user"] },
    },
    { upsert: true },
  );

  return {
    suiteConfig: {
      alias: input.alias,
      description: `Noirly Identity at ${issuer}`,
      server: { discoveryUrl: `${issuer}/.well-known/openid-configuration` },
      client: clients[0]!,
      client2: clients[1]!,
      browser: [],
    },
    account: { email: CONFORMANCE_EMAIL, password },
  };
}

/** Removes the suite's clients and test account. */
export async function removeConformanceSetup() {
  const clients = await OAuthClient.deleteMany({ clientId: { $in: [...CONFORMANCE_CLIENT_IDS] } });
  const users = await User.deleteMany({ email: CONFORMANCE_EMAIL });
  return { clients: clients.deletedCount, users: users.deletedCount };
}
