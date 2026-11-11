import { getEnv } from "@/lib/config/env";

/**
 * Sending text messages, for phone verification only. Production sends
 * through an approved provider (Twilio) or not at all; development logs
 * that a message went, never its code.
 */

export type SmsMessage = { to: string; body: string; kind: string };

export interface SmsProvider {
  send(message: SmsMessage): Promise<void>;
}

class DevelopmentSmsProvider implements SmsProvider {
  async send(message: SmsMessage): Promise<void> {
    // Development only: the number half hidden, and no code.
    console.info("[sms:dev]", { kind: message.kind, to: `${message.to.slice(0, 4)}…${message.to.slice(-2)}` });
  }
}

class TwilioSmsProvider implements SmsProvider {
  async send(message: SmsMessage): Promise<void> {
    const env = getEnv();
    const sid = env.TWILIO_ACCOUNT_SID!;
    const from = env.TWILIO_FROM!;
    const body = new URLSearchParams({ To: message.to, Body: message.body, ...(from.startsWith("MG") ? { MessagingServiceSid: from } : { From: from }) });
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${sid}:${env.TWILIO_AUTH_TOKEN}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Twilio refused the message (HTTP ${response.status})`);
  }
}

let provider: SmsProvider | null = null;

/** Which provider is in use: set by SMS_PROVIDER, or development locally and none in production. */
export function smsMode(): "none" | "development" | "twilio" {
  const env = getEnv();
  const mode = env.SMS_PROVIDER ?? (env.NODE_ENV === "production" ? "none" : "development");
  if (mode === "twilio" && !(env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_FROM)) return "none";
  return mode;
}

export function isSmsAvailable(): boolean {
  return Boolean(provider) || smsMode() !== "none";
}

function getSmsProvider(): SmsProvider | null {
  if (provider) return provider;
  const mode = smsMode();
  if (mode === "none") return null;
  provider = mode === "twilio" ? new TwilioSmsProvider() : new DevelopmentSmsProvider();
  return provider;
}

export function setSmsProvider(next: SmsProvider | null): void {
  provider = next;
}

export async function sendSms(message: SmsMessage): Promise<void> {
  const current = getSmsProvider();
  if (!current) throw new Error("No text message provider is set up");
  await current.send(message);
}
