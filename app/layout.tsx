import { headers } from "next/headers";
import type { Metadata } from "next";
import { NoirlyHead, noirlyFontClassName } from "@noirly-dev/ui";
import { NoirlyExperience } from "@noirly-dev/ui/experience";
import { AppProviders } from "@/components/AppProviders";
import { getRequestUser } from "@/lib/auth/request-user";
import "./globals.css";

export const metadata: Metadata = {
  title: "Noirly Identity",
  description: "Central authentication and SSO for the Noirly ecosystem",
  icons: {
    icon: [
      {
        url: "/brand-mark-light.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: light)",
      },
      {
        url: "/brand-mark-dark.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: dark)",
      },
    ],
  },
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  // A signed-in account's language and accessibility settings shape these pages too.
  const user = await getRequestUser().catch(() => null);
  const accessibility = user?.accessibility;
  return (
    <html
      lang={user?.locale ?? "en"}
      className="dark h-full"
      data-theme="gold"
      data-motion={accessibility?.motion === "reduce" ? "reduce" : undefined}
      data-contrast={accessibility?.contrast === "more" ? "more" : undefined}
      data-text-size={accessibility && accessibility.textSize !== "default" ? accessibility.textSize : undefined}
      suppressHydrationWarning
    >
      <head>
        <NoirlyHead themeId="gold" nonce={nonce} />
      </head>
      <body className={`${noirlyFontClassName} flex min-h-dvh flex-col antialiased`}>
        <NoirlyExperience mark="Noirly Identity" pageTransition={false} cursor={false}>
          <AppProviders>{children}</AppProviders>
        </NoirlyExperience>
      </body>
    </html>
  );
}
