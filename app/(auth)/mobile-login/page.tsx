import { redirect } from "next/navigation";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { hashToken } from "@/lib/security/crypto";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { requirePublicMobileClient } from "@/lib/mobile/mint-tokens";
import { MobileLoginApproval } from "@/components/security/MobileLoginApproval";

export default async function MobileLoginPage({ searchParams }: { searchParams: Promise<{ request?: string }> }) {
  const { request } = await searchParams;
  if (!request || request.length > 128) return <p>Invalid mobile sign-in request.</p>;
  const record = await withDb(() => MobileBrowserLogin.findOne({ requestHash: hashToken(request), expiresAt: { $gt: new Date() } }).lean());
  if (!record) return <p>Mobile sign-in expired. Start again from the app.</p>;
  const user = await getRequestUser();
  if (!user) redirect(`/login?return_to=${encodeURIComponent(`/mobile-login?request=${encodeURIComponent(request)}`)}`);
  const client = await withDb(() => requirePublicMobileClient(record.clientId));
  return <main className="mx-auto w-full max-w-md px-6 py-12"><MobileLoginApproval request={request} appName={client.name} email={user.email} /></main>;
}
