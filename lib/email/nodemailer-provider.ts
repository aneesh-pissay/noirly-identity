import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import { getEnv } from "@/lib/config/env";
import type { EmailMessage, EmailProvider } from "@/lib/email/email-service";

export class NodemailerEmailProvider implements EmailProvider {
  private transporter: Transporter | null = null;

  private getTransporter(): Transporter {
    if (this.transporter) {
      return this.transporter;
    }

    const env = getEnv();
    if (
      !env.SMTP_HOST ||
      !env.SMTP_PORT ||
      !env.EMAIL_FROM ||
      env.SMTP_USER === undefined ||
      env.SMTP_PASS === undefined
    ) {
      throw new Error(
        "SMTP email provider requires SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and EMAIL_FROM",
      );
    }

    this.transporter = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: Boolean(env.SMTP_SECURE),
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
      },
    });

    return this.transporter;
  }

  async send(message: EmailMessage): Promise<void> {
    const env = getEnv();
    try {
      await this.getTransporter().sendMail({
        from: env.EMAIL_FROM,
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      });
    } catch (error) {
      const err = error as { code?: string; responseCode?: number; message?: string };
      console.error("[email:smtp] send failed", {
        code: err.code,
        responseCode: err.responseCode,
      });
      throw new Error("Failed to send email");
    }
  }
}
