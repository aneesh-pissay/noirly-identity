import { redirect } from "next/navigation";
import { LoginPageClient } from "./LoginForm";
import { getRequestUser } from "@/lib/auth/request-user";
import { isPopupLogin, sanitizeReturnTo } from "@/lib/auth/return-to";
import { getEnv } from "@/lib/config/env";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{
    return_to?: string;
    popup?: string;
    select_account?: string;
    reauth?: string;
  }>;
}) {
  const [params, user] = await Promise.all([searchParams, getRequestUser()]);
  const selectAccount = params.select_account === "1";

  if (user && !selectAccount && params.reauth !== "1") {
    redirect(
      sanitizeReturnTo(params.return_to, getEnv().APP_URL) ?? "/account",
    );
  }

  return (
    <LoginPageClient
      popup={isPopupLogin(params.popup)}
      currentEmail={user?.email ?? null}
      selectAccount={selectAccount}
    />
  );
}
