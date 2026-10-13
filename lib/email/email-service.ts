import { getEnv } from "@/lib/config/env";
import { NodemailerEmailProvider } from "@/lib/email/nodemailer-provider";
import { redactSecretInUrl } from "@/lib/email/templates";

export type EmailMessage = {
  to: string;
  subject: string;
  text: string;
  html?: string;
  meta?: {
    kind?: string;
    previewUrl?: string;
  };
};

export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}

export class DevelopmentEmailProvider implements EmailProvider {
  async send(message: EmailMessage): Promise<void> {
    const preview =
      message.meta?.previewUrl ||
      redactSecretInUrl(
        message.text.match(/https?:\/\/\S+/)?.[0] ?? "",
      );

    // Development-only: never log raw verification/reset tokens.
    console.info("[email:dev]", {
      kind: message.meta?.kind ?? "generic",
      previewUrl: preview || undefined,
      note: "Raw tokens are redacted. Open the emailed link (or SMTP inbox) to verify.",
    });
  }
}

let provider: EmailProvider | null = null;

export function getEmailProvider(): EmailProvider {
  if (provider) {
    return provider;
  }

  const mode = getEnv().EMAIL_PROVIDER;
  provider =
    mode === "smtp" ? new NodemailerEmailProvider() : new DevelopmentEmailProvider();
  return provider;
}

export function setEmailProvider(next: EmailProvider): void {
  provider = next;
}

export function resetEmailProvider(): void {
  provider = null;
}

export async function sendEmail(message: EmailMessage): Promise<void> {
  await getEmailProvider().send(message);
}
