import { Home, KeyRound, Laptop, Settings, ShieldCheck, User, type LucideIcon } from "lucide-react";

export type NavItem = { href: string; label: string; icon: LucideIcon };

/** The account's five areas, plus Home (shared by the sidebar and the home page). */
export const ACCOUNT_AREAS: NavItem[] = [
  { href: "/account", label: "Home", icon: Home },
  { href: "/account/profile", label: "Personal info", icon: User },
  { href: "/account/security", label: "Security", icon: KeyRound },
  { href: "/account/devices", label: "Devices", icon: Laptop },
  { href: "/account/privacy", label: "Privacy and apps", icon: ShieldCheck },
  { href: "/account/manage", label: "Account", icon: Settings },
];
