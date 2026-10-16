import { headers } from "next/headers";
import type { Metadata } from "next";
import { NoirlyHead, noirlyFontClassName } from "@noirly-dev/ui";
import { NoirlyExperience } from "@noirly-dev/ui/experience";
import { AppProviders } from "@/components/AppProviders";
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
  return (
    <html
      lang="en"
      className="dark h-full"
      data-theme="gold"
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
