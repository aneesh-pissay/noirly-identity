import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, LegalSection } from "@/components/LegalPage";
import { LEGAL, privacyContactEmail } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Privacy policy · Noirly Identity",
  description: "What Noirly Identity — the Noirly account and sign-in service — collects, why, how long it is kept, and how to delete it.",
};

export default function PrivacyPage() {
  const contact = privacyContactEmail();
  const contactLine = contact ? (
    <>
      email <a href={`mailto:${contact}`}>{contact}</a>
    </>
  ) : (
    <>reply to any email you have received from Noirly</>
  );

  return (
    <LegalPage
      eyebrow={`Noirly Identity · Effective ${LEGAL.effectiveDate}`}
      title="Privacy policy"
      lead={
        <p>
          Noirly Identity is the Noirly account: the email, password or Google sign-in you use for every Noirly app. This
          policy explains what Identity collects, why, who it is shared with, how long it is kept and how to delete it. We
          collect what sign-in needs, never sell it, and use no ads or trackers.
        </p>
      }
    >
      <LegalSection id="who" title="Who we are">
        <p>
          Noirly Identity ({LEGAL.host}) is run by {LEGAL.operator}, based in {LEGAL.country}, who is responsible for your
          account data (&ldquo;we&rdquo;, &ldquo;us&rdquo;).
        </p>
        <p>
          This policy covers <strong>only your account and sign-in</strong>. Each Noirly app you use with your account
          keeps its own data and has its own privacy policy:
        </p>
        <ul>
          {LEGAL.apps.map((app) => (
            <li key={app.name}>
              <a href={app.privacyUrl}>{app.name} privacy policy</a> ({app.what})
            </li>
          ))}
        </ul>
      </LegalSection>

      <LegalSection id="collect" title="What we collect">
        <ul>
          <li>
            <strong>Your account:</strong> email address; first, last and display name; and, if you add them, a phone
            number and profile picture.
          </li>
          <li>
            <strong>Your password</strong>, if you set one, stored only as a one-way hash (Argon2), never the password
            itself.
          </li>
          <li>
            <strong>Google sign-in</strong>, if you use it: your Google account ID, email, name and picture from Google,
            and the link between that Google ID and your account.
          </li>
          <li>
            <strong>Sign-in records:</strong> for each session, when it started and was last used, its expiry, and the IP
            address and browser or device description (user agent) it came from.
          </li>
          <li>
            <strong>Short-lived codes</strong> for email verification and password resets, stored hashed.
          </li>
          <li>
            <strong>App connections:</strong> which Noirly apps you have signed in to and the permissions (scopes) you
            approved for them.
          </li>
        </ul>
        <p>We do not collect your location, contacts, advertising IDs or usage analytics.</p>
      </LegalSection>

      <LegalSection id="use" title="How we use it">
        <ul>
          <li>To create your account, sign you in, and keep your sessions secure.</li>
          <li>To sign you in to Noirly apps without a separate password for each.</li>
          <li>To send account emails: verification, password resets and security notices. We do not send marketing email.</li>
          <li>To prevent abuse, for example by rate-limiting sign-in attempts.</li>
        </ul>
        <p>We do not sell your data, use it for advertising, or build profiles of you.</p>
      </LegalSection>

      <LegalSection id="share" title="Who we share it with">
        <ul>
          <li>
            <strong>Noirly apps you sign in to</strong> receive your account ID and, for the permissions you approve, your
            name, email and picture. What each app then does with it is set out in that app&apos;s own policy.
          </li>
          <li>
            <strong>Service providers</strong> that run Identity for us and process data only on our instructions: server
            and database hosting, and an email delivery service for account emails.
          </li>
          <li>
            <strong>Google</strong>, only if you choose &ldquo;Sign in with Google&rdquo;, under Google&apos;s own privacy
            policy.
          </li>
          <li>
            <strong>Authorities</strong>, only if the law requires it.
          </li>
        </ul>
        <p>We do not share your data with anyone else.</p>
      </LegalSection>

      <LegalSection id="device" title="Cookies and your browser">
        <p>
          Identity uses only strictly necessary cookies: a session cookie that keeps you signed in and a security (CSRF)
          cookie. It also remembers your theme and the emails you recently signed in with in your browser&apos;s local
          storage, which never leaves your device.
        </p>
      </LegalSection>

      <LegalSection id="security" title="Security">
        <p>
          All traffic is encrypted in transit (HTTPS). Passwords are hashed with Argon2, and sessions, access and refresh
          tokens are stored only as hashes. Access is limited to what is needed to run the service.
        </p>
      </LegalSection>

      <LegalSection id="retention" title="How long we keep it">
        <ul>
          <li>Your account: for as long as you keep it.</li>
          <li>Sessions: until you sign out or they expire (14 days without use on the web; app sign-ins renew for up to 30 days).</li>
          <li>Email verification and password-reset codes: until used, or at most 24 hours.</li>
          <li>
            When you delete your account, we delete it straight away (see below). Copies in our hosting provider&apos;s
            backups are overwritten on their normal backup cycle.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="delete" title="Deleting your account">
        <p>
          You can delete your Noirly account at any time at{" "}
          <Link href="/delete-account">{LEGAL.host}/delete-account</Link>, or from inside a Noirly app that offers it (for
          example Noirly Flow: Menu → Delete account).
        </p>
        <p>
          This removes your account, your password hash, your Google sign-in link, and all your sessions and app
          sign-ins. Every device is signed out. We also tell the Noirly apps you used (such as Noirly Flow) that the account
          is gone, so they delete the data they hold for it as their own policies describe. This cannot be undone.
        </p>
      </LegalSection>

      <LegalSection id="rights" title="Your choices and rights">
        <p>
          You can see and correct your details on your <Link href="/account">account page</Link>, change your password, and
          delete your account as described above. Depending on where you live (including under India&apos;s Digital
          Personal Data Protection Act, 2023), you may also have the right to request a copy of your data, to have it
          corrected or erased, and to complain to a data protection authority. To make a request, {contactLine}.
        </p>
      </LegalSection>

      <LegalSection id="children" title="Children">
        <p>
          Noirly accounts are not meant for children under 13, and we do not knowingly collect their data. If you believe a
          child has created an account, contact us and we will delete it.
        </p>
      </LegalSection>

      <LegalSection id="changes" title="Changes to this policy">
        <p>
          If we change this policy, we will update the date at the top of this page. For significant changes we will tell
          you by email before they take effect.
        </p>
      </LegalSection>

      <LegalSection id="contact" title="Contact">
        <p>Questions about your Noirly account and privacy? Please {contactLine}.</p>
      </LegalSection>
    </LegalPage>
  );
}
