import type { Metadata } from "next";
import Link from "next/link";
import { Button } from "@noirly-dev/ui";
import { DeleteAccountForm } from "@/components/DeleteAccountForm";
import { LegalPage, LegalSection } from "@/components/LegalPage";
import { getRequestUser } from "@/lib/auth/request-user";
import { privacyContactEmail } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Delete your account · Noirly",
  description: "How to delete your Noirly account and the data deleted with it, from the Noirly Flow app or the web.",
};

export default async function DeleteAccountPage() {
  const user = await getRequestUser();
  const contact = privacyContactEmail();

  return (
    <LegalPage
      eyebrow="Noirly Identity · Noirly Flow"
      title="Delete your Noirly account"
      lead={
        <p>
          Deleting your account removes it from Noirly Identity and deletes your Noirly Flow data. It happens straight
          away and cannot be undone.
        </p>
      }
    >
      <LegalSection id="now" title={user ? "Delete it now" : "Delete it on the web"}>
        {user ? (
          <DeleteAccountForm email={user.email} hasPassword={user.hasPassword} />
        ) : (
          <>
            <p>Sign in to the account you want to delete, then confirm with your password on this page.</p>
            <div>
              <Button asChild size="lg">
                <Link href="/login?return_to=/delete-account">Sign in to delete your account</Link>
              </Button>
            </div>
          </>
        )}
      </LegalSection>

      <LegalSection id="app" title="Or from the Noirly Flow Android app">
        <ul>
          <li>Open Noirly Flow and sign in.</li>
          <li>Open the <strong>Menu</strong> tab.</li>
          <li>
            Tap <strong>Delete account</strong>, confirm with your password (or, for Google sign-in, your email), and
            tap <strong>Delete</strong>.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="what" title="What is deleted">
        <ul>
          <li>Your Noirly account: name, email, phone, profile picture, password hash and Google sign-in link.</li>
          <li>All your sign-in sessions and app tokens. Every device is signed out.</li>
          <li>Your Noirly Flow profile and your personal workspace with all its projects, tasks and comments.</li>
          <li>Team workspaces where you are the only member, with everything in them.</li>
          <li>In team workspaces you share with others: your membership, your comments and your activity history.</li>
        </ul>
      </LegalSection>

      <LegalSection id="kept" title="What is kept">
        <ul>
          <li>
            Tasks you created in a team workspace that others still use stay with that team, without your name on them.
            If you owned the workspace, ownership passes to another member.
          </li>
          <li>
            Copies in our hosting provider&apos;s backups, until they are overwritten on the normal backup cycle.
          </li>
        </ul>
        <p>
          The details are in the <Link href="/privacy#delete">privacy policy</Link>.
        </p>
      </LegalSection>

      <LegalSection id="help" title="Can't sign in?">
        <p>
          Reset your password from the <Link href="/forgot-password">forgot password</Link> page, then come back
          here.{" "}
          {contact ? (
            <>
              If that doesn&apos;t work, email <a href={`mailto:${contact}`}>{contact}</a> from the address on the
              account and ask us to delete it. We will confirm and delete it within 30 days.
            </>
          ) : null}
        </p>
      </LegalSection>
    </LegalPage>
  );
}
