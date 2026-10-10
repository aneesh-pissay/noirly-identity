import type { Metadata } from "next";
import Link from "next/link";
import { Button } from "@noirly-dev/ui";
import { DeleteAccountForm } from "@/components/DeleteAccountForm";
import { LegalPage, LegalSection } from "@/components/LegalPage";
import { getRequestUser } from "@/lib/auth/request-user";
import { privacyContactEmail } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Delete your account · Noirly",
  description: "How to delete your Noirly account and the data deleted with it, from the Noirly Flow or Noirly Ledger app or the web.",
};

export default async function DeleteAccountPage() {
  const user = await getRequestUser();
  const contact = privacyContactEmail();

  return (
    <LegalPage
      eyebrow="Noirly Identity · Noirly Flow · Noirly Ledger"
      title="Delete your Noirly account"
      lead={
        <p>
          Deleting your account removes it from Noirly Identity and deletes your data in the Noirly apps you used
          (Noirly Flow and Noirly Ledger). It happens straight away and cannot be undone.
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

      <LegalSection id="app" title="Or from an Android app">
        <ul>
          <li>
            <strong>Noirly Flow:</strong> open the <strong>Menu</strong> tab and tap <strong>Delete account</strong>.
          </li>
          <li>
            <strong>Noirly Ledger:</strong> open the <strong>Settings</strong> tab and tap <strong>Delete account</strong>.
          </li>
          <li>
            Confirm with your password (or, for Google sign-in, your email), and tap <strong>Delete</strong>. Either app
            deletes the whole account, including your data in the other app.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="what" title="What is deleted">
        <ul>
          <li>Your Noirly account: name, email, phone, profile picture, password hash and Google sign-in link.</li>
          <li>All your sign-in sessions and app tokens. Every device is signed out.</li>
          <li>Your Noirly Flow profile and your personal workspace with all its projects, tasks and comments.</li>
          <li>
            Your Noirly Ledger profile and your personal workspace with all its transactions, budgets, goals and
            receipts.
          </li>
          <li>Team workspaces where you are the only member, with everything in them.</li>
          <li>
            In team workspaces you share with others: your membership, your Flow comments and activity history, and your
            Ledger notifications and invites.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="kept" title="What is kept">
        <ul>
          <li>
            Tasks you created in a team workspace, and expenses you submitted to a shared Ledger workspace, stay with that
            team (they are its records), no longer linked to you. If you owned the workspace, ownership passes to another
            member.
          </li>
          <li>
            Copies in our hosting provider&apos;s backups, until they are overwritten on the normal backup cycle.
          </li>
        </ul>
        <p>
          Details: the <Link href="/privacy#delete">Noirly Identity</Link>,{" "}
          <a href="https://noirly.flow.aneesh-pissay.in/privacy#delete">Noirly Flow</a> and{" "}
          <a href="https://noirly.ledger.aneesh-pissay.in/privacy#delete">Noirly Ledger</a> privacy policies.
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
