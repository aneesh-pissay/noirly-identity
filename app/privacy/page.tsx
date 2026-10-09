import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, LegalSection } from "@/components/LegalPage";
import { LEGAL, privacyContactEmail } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Privacy policy · Noirly",
  description: "What Noirly Identity and Noirly Flow collect, why, how long it is kept, and how to delete it.",
};

export default function PrivacyPage() {
  const contact = privacyContactEmail();

  return (
    <LegalPage
      eyebrow={`Effective ${LEGAL.effectiveDate}`}
      title="Privacy policy"
      lead={
        <p>
          This policy explains what Noirly collects when you use Noirly Identity and Noirly Flow (on the web and the
          Android app), why, who it is shared with, how long it is kept, and how you can delete it. In short: we collect
          what the apps need to work, we never sell it, and there are no ads or third-party trackers.
        </p>
      }
    >
      <LegalSection id="who" title="Who we are">
        <p>
          Noirly is run by {LEGAL.operator}, based in {LEGAL.country}, who is responsible for your data
          (&ldquo;we&rdquo;, &ldquo;us&rdquo;). This policy covers:
        </p>
        <ul>
          {LEGAL.products.map((product) => (
            <li key={product.name}>
              <strong>{product.name}</strong>: {product.what} ({product.host})
            </li>
          ))}
        </ul>
      </LegalSection>

      <LegalSection id="collect" title="What we collect">
        <p>
          <strong>Your account (Noirly Identity).</strong> Your email address, first, last and display name, and
          optionally a phone number and profile picture. If you use a password, we store only a one-way hash of it
          (Argon2), never the password itself. If you sign in with Google, we receive your Google account ID, email,
          name and picture from Google, and we link that Google ID to your account.
        </p>
        <p>
          <strong>Sign-in records.</strong> For each signed-in session we keep when it started and was last used, its
          expiry, and the IP address and browser or device description (user agent) it came from. We use these to keep
          you signed in, let you sign out everywhere, and spot misuse. Short-lived codes for email verification and
          password resets are stored hashed.
        </p>
        <p>
          <strong>What you create in Noirly Flow.</strong> Workspaces, projects, board columns, tasks (titles,
          descriptions, due and start dates, checklists, repeats, tags, assignees), comments, workspace invites, your
          Flow profile (display name, title, timezone, bio), and an activity history of changes in each workspace that
          its members can see.
        </p>
        <p>
          <strong>Presence.</strong> While you have a project open, other members of that workspace can see that you are
          online and viewing it. This is not stored after you leave.
        </p>
        <p>
          <strong>We do not collect</strong> your location, contacts, photos, files from your device, advertising IDs,
          or usage analytics. The Android app asks only for internet access and has no ads, analytics or crash-reporting
          SDKs.
        </p>
      </LegalSection>

      <LegalSection id="use" title="How we use it">
        <ul>
          <li>To create your account, sign you in, and keep your sessions secure.</li>
          <li>To provide Noirly Flow: store, sync and show your tasks and workspaces to you and the people you share them with.</li>
          <li>To send account emails: verification, password resets and security notices. We do not send marketing email.</li>
          <li>To prevent abuse, for example by rate-limiting sign-in attempts.</li>
        </ul>
        <p>
          We use your data only to run these services. We do not sell it, use it for advertising, or build profiles of
          you.
        </p>
      </LegalSection>

      <LegalSection id="share" title="Who can see it, and who we share it with">
        <ul>
          <li>
            <strong>People in your workspaces</strong> see your name, picture, the tasks and comments you add, and your
            activity in workspaces you share with them. Personal workspaces are visible only to you.
          </li>
          <li>
            <strong>Service providers</strong> that run Noirly for us and process data only on our instructions:
            database and server hosting, and an email delivery service for account emails.
          </li>
          <li>
            <strong>Google</strong>, only if you choose &ldquo;Sign in with Google&rdquo;, under Google&apos;s own
            privacy policy.
          </li>
          <li>
            <strong>Authorities</strong>, only if the law requires it.
          </li>
        </ul>
        <p>We do not share your data with anyone else.</p>
      </LegalSection>

      <LegalSection id="device" title="On your device">
        <p>
          The website uses a small number of cookies that are strictly needed: a session cookie that keeps you signed
          in and a security (CSRF) cookie. It also remembers your theme and the emails you recently signed in with in
          your browser&apos;s local storage; this never leaves your device. The Android app keeps its sign-in tokens in
          Android&apos;s encrypted keystore and removes them when you sign out.
        </p>
      </LegalSection>

      <LegalSection id="security" title="Security">
        <p>
          All traffic is encrypted in transit (HTTPS and secure WebSockets). Passwords are hashed with Argon2, and
          sessions, access and refresh tokens are stored only as hashes. Access is limited to what is needed to run the
          service.
        </p>
      </LegalSection>

      <LegalSection id="retention" title="How long we keep it">
        <ul>
          <li>Your account and Flow data: for as long as you keep your account.</li>
          <li>Sessions: until you sign out or they expire (14 days without use for the website; app sign-ins renew for up to 30 days).</li>
          <li>Email verification and password-reset codes: until used, or at most 24 hours.</li>
          <li>
            When you delete your account, we delete it straight away (see below). Copies in our hosting provider&apos;s
            backups are overwritten on their normal backup cycle.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="delete" title="Deleting your account and data">
        <p>You can delete your Noirly account at any time:</p>
        <ul>
          <li>
            <strong>In the Noirly Flow Android app:</strong> Menu → Delete account.
          </li>
          <li>
            <strong>On the web:</strong> <Link href="/delete-account">noirly.identity.aneesh-pissay.in/delete-account</Link>.
          </li>
        </ul>
        <p>
          Deleting your account removes your Noirly Identity account, your sign-in records and Google link, and your
          Noirly Flow data: your personal workspace, team workspaces where you are the only member, and your comments
          and activity. In team workspaces shared with others, the tasks you created stay with the team (they belong to
          the workspace) but are no longer linked to your name, and ownership passes to another member. This cannot be
          undone.
        </p>
      </LegalSection>

      <LegalSection id="rights" title="Your choices and rights">
        <p>
          You can see and correct your account details on your <Link href="/account">account page</Link>, change your
          Flow profile in the app, export a workspace&apos;s activity as CSV, and delete your account as described
          above. Depending on where you live (including under India&apos;s Digital Personal Data Protection Act, 2023),
          you may also have the right to request a copy of your data, to have it corrected or erased, and to complain to
          a data protection authority.{" "}
          {contact ? (
            <>
              To make a request, email <a href={`mailto:${contact}`}>{contact}</a>.
            </>
          ) : (
            <>To make a request, reply to any email you have received from Noirly.</>
          )}
        </p>
      </LegalSection>

      <LegalSection id="children" title="Children">
        <p>
          Noirly is not meant for children under 13, and we do not knowingly collect their data. If you believe a child
          has created an account, contact us and we will delete it.
        </p>
      </LegalSection>

      <LegalSection id="changes" title="Changes to this policy">
        <p>
          If we change this policy, we will update the date at the top of this page. For significant changes we will
          tell you by email or in the apps before they take effect.
        </p>
      </LegalSection>

      <LegalSection id="contact" title="Contact">
        <p>
          Questions about privacy?{" "}
          {contact ? (
            <>
              Email <a href={`mailto:${contact}`}>{contact}</a>.
            </>
          ) : (
            <>Reply to any email you have received from Noirly.</>
          )}
        </p>
      </LegalSection>
    </LegalPage>
  );
}
