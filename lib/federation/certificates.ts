import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { parseCertificate, parseIdpMetadata } from "@/lib/federation/providers";
import { IdentityProvider, type IdentityProviderDocument, type SamlCertificate } from "@/models/IdentityProvider";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { User } from "@/models/User";

/**
 * Federation certificate monitoring (the scheduled job):
 * - SAML IdPs with a metadata URL: new signing certificates are picked up
 *   from it, so the IdP's own rollover needs nothing from the admin;
 * - certificates within 30 days of expiry are reported, once each, to the
 *   organization's owners (and admins with the domains area);
 * - an expired certificate is dropped once a valid one remains.
 * (OIDC IdPs rotate through their JWKS, which sign-in re-reads on a miss.)
 */

const WARN_DAYS = 30;

async function recipients(organizationId: IdentityProviderDocument["organizationId"]) {
  const members = await OrganizationMembership.find({ organizationId, $or: [{ role: "owner" }, { role: "admin", adminAreas: "domains" }] }).select("userId").lean();
  return (await User.find({ _id: { $in: members.map((m) => m.userId) } }).select("email").lean()).map((u) => u.email);
}

async function fromMetadata(url: string): Promise<SamlCertificate[] | null> {
  try {
    const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(8000), cache: "no-store" });
    if (!res.ok) return null;
    return parseIdpMetadata(await res.text()).certificates.map(parseCertificate);
  } catch {
    return null;
  }
}

export async function checkFederationCertificates(now = new Date()): Promise<{ expiring: number; rotated: number; removed: number }> {
  const stats = { expiring: 0, rotated: 0, removed: 0 };
  const warnBefore = now.getTime() + WARN_DAYS * 86_400_000;
  for (const idp of await IdentityProvider.find({ protocol: "saml" }).lean<IdentityProviderDocument[]>()) {
    const spaceId = String(idp.organizationId);
    let certs = [...idp.saml!.certificates];

    if (idp.saml!.metadataUrl) {
      const published = await fromMetadata(idp.saml!.metadataUrl);
      const fresh = (published ?? []).filter((c) => !certs.some((k) => k.fingerprint === c.fingerprint) && c.notAfter.getTime() > now.getTime());
      if (fresh.length) {
        certs = [...certs, ...fresh];
        stats.rotated += fresh.length;
        await recordEvent({ action: "sso.certificate_rotated", stream: orgStream(spaceId), actorId: null, subjectId: null, data: { organizationId: spaceId, idpId: String(idp._id), added: fresh.map((c) => c.fingerprint) } });
      }
    }

    const valid = certs.filter((c) => c.notAfter.getTime() > now.getTime());
    if (valid.length && valid.length < certs.length) {
      stats.removed += certs.length - valid.length;
      certs = valid;
    }

    // Warn only when nothing valid will outlast the window.
    const lastsBeyond = certs.some((c) => c.notAfter.getTime() > warnBefore);
    const due = lastsBeyond ? [] : certs.filter((c) => !c.alertedAt);
    if (due.length) {
      stats.expiring += due.length;
      const soonest = new Date(Math.max(...certs.map((c) => c.notAfter.getTime())));
      const to = await recipients(idp.organizationId);
      await Promise.all(
        to.map((email) =>
          sendEmail({
            to: email,
            ...buildNoticeEmail({
              subject: `${idp.name}'s signing certificate expires soon`,
              paragraphs: [
                `The certificate ${idp.name} signs sign-ins with expires on ${soonest.toDateString()}. After that, nobody can sign in through it.`,
                "Add the new certificate from your identity provider (or its metadata URL) to the space's single sign-on settings before then.",
              ],
              action: { label: "Open single sign-on settings", url: new URL("/spaces", getEnv().APP_URL).toString() },
            }),
            meta: { kind: "federation-certificate" },
          }).catch(() => undefined),
        ),
      );
      await recordEvent({ action: "sso.certificate_expiring", stream: orgStream(spaceId), actorId: null, subjectId: null, data: { organizationId: spaceId, idpId: String(idp._id), notAfter: soonest.toISOString() } });
      certs = certs.map((c) => (due.includes(c) ? { ...c, alertedAt: now } : c));
    }

    if (JSON.stringify(certs) !== JSON.stringify(idp.saml!.certificates)) {
      await IdentityProvider.updateOne({ _id: idp._id }, { $set: { "saml.certificates": certs } });
    }
  }
  return stats;
}
