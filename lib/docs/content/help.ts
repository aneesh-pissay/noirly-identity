import type { DocArticle } from "@/lib/docs/types";

export const help: DocArticle[] = [
  {
    id: "troubleshooting",
    category: "help",
    kind: "guide",
    title: "Troubleshooting",
    summary: "Fixes for the problems people run into most.",
    introduction: "Start here when something doesn't work. Each feature's page has its own troubleshooting too.",
    troubleshooting: [
      { problem: "I can't sign in and don't know why", solution: "Type your address on the sign-in page: it shows the ways that address can use. If none work, use Email me a sign-in link instead." },
      { problem: "The confirmation or sign-in email never arrives", solution: "Check spam and the address. Links expire; ask for a new one and use the newest." },
      { problem: "I lost my phone with the authenticator", solution: "Use a recovery code or passkey. Without either, choose Lost your authenticator app, passkey or security key? after your password." },
      { problem: "Someone else is in my account", solution: "Freeze it from any security alert's link, or from your account page. Then change your password." },
      { problem: "An app says I have no access", solution: "It may be limited to certain spaces, teams or people. Ask the app's owner or your space admin." },
      { problem: "I keep being asked to sign in again", solution: "A space you're in has short session limits, or allows only certain sign-in methods." },
      { problem: "I'm sent to my company's sign-in page", solution: "Your organization requires single sign-on for your address. Sign in there." },
      { problem: "“Too many attempts”", solution: "Wait a few minutes. Repeated tries from one network are slowed down to stop guessing." },
    ],
    faqs: [
      { question: "Can Noirly staff see my password?", answer: "No. Passwords are stored only as Argon2 hashes." },
      { question: "Why does a change ask me to sign in again?", answer: "Security changes need a sign-in within the last five minutes, so an unlocked computer isn't enough to take over the account." },
      { question: "Is there a light theme?", answer: "Yes: the switch at the top right of every page, with a choice of accent colours." },
      { question: "Where's the privacy policy?", answer: "At `/privacy`, linked from every page's footer and the account page." },
    ],
    related: ["signing-in", "losing-your-second-step", "freezing-your-account", "single-sign-on"],
    sources: ["app/(auth)/login", "app/(auth)/no-access/page.tsx", "lib/security/rate-limit.ts", "app/privacy/page.tsx"],
    keywords: ["help", "problem", "not working", "faq", "support"],
    video: { unavailable: "A collection of fixes rather than one workflow; each feature's page has its walkthrough." },
  },
];
