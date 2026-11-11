import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { confirmEmailVerification } from "@/lib/auth/auth-service";
import { jsonResponse } from "@/lib/security/headers";
import { verifyEmailSchema } from "@/lib/validation/schemas";

function statusPayload(status: string) {
  switch (status) {
    case "verified":
      return {
        status: "verified",
        message: "Your email address has been verified.",
      };
    case "already_verified":
      return {
        status: "already_verified",
        message: "Your email address has already been verified.",
      };
    case "expired":
      return {
        status: "expired",
        message: "This verification link has expired.",
      };
    case "taken":
      return {
        status: "invalid",
        message: "This address was confirmed on another account first, so it can't be added.",
      };
    case "used":
      return {
        status: "used",
        message: "This verification link is invalid or has already been used.",
      };
    default:
      return {
        status: "invalid",
        message: "This verification link is invalid or has already been used.",
      };
  }
}

async function verify(token: string) {
  const result = await confirmEmailVerification(token);
  const payload = statusPayload(result.status);
  const ok = result.status === "verified" || result.status === "already_verified";
  return jsonResponse(payload, { status: ok ? 200 : 400 });
}

export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-verify-email", 30, 60);
      const token = request.nextUrl.searchParams.get("token") ?? "";
      const parsed = verifyEmailSchema.safeParse({ token });
      if (!parsed.success) {
        return jsonResponse(statusPayload("invalid"), { status: 400 });
      }
      return verify(parsed.data.token);
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-verify-email", 30, 60);
      const body = await readJsonBody(request);
      const parsed = verifyEmailSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(statusPayload("invalid"), { status: 400 });
      }
      return verify(parsed.data.token);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
