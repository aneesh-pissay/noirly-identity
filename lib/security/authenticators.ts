/**
 * What a passkey or security key is, as far as it tells us: its AAGUID
 * (a model id the authenticator reports), whether it's synced across
 * devices, and whether it attested to that with a signed statement. Shared
 * by the server and the account page, so it holds no server code.
 *
 * An attestation's signature is checked when the key is added, but not
 * traced back to the maker's root certificate (that needs the FIDO metadata
 * service), so the model shown is what the device says it is.
 */

export type AuthenticatorKind = "passkey" | "security_key";

/** Well-known AAGUIDs. Anything else shows by its kind. */
const KNOWN: Record<string, string> = {
  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
  "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
  "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
  "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
  "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (managed)",
  "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
  "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
  "53414d53-554e-4700-0000-000000000000": "Samsung Pass",
  "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series",
  "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
  "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 Series with NFC",
  "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series with NFC",
  "c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5Ci",
  "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": "Security Key NFC by Yubico",
  "0bb43545-fd2c-4185-87dd-feb0b2916ace": "Security Key NFC by Yubico (Enterprise)",
};

const EMPTY_AAGUID = "00000000-0000-0000-0000-000000000000";

export function authenticatorModel(aaguid: string | null | undefined): string | null {
  if (!aaguid || aaguid === EMPTY_AAGUID) return null;
  return KNOWN[aaguid.toLowerCase()] ?? null;
}

export type AuthenticatorFacts = {
  kind: AuthenticatorKind;
  aaguid?: string | null;
  attestationFormat?: string | null;
  synced?: boolean | null;
  standalone?: boolean | null;
};

export type AuthenticatorDetails = {
  kindLabel: string;
  model: string | null;
  attested: boolean;
  /** Short facts for the list: "Synced", "Second step only", "Attested (packed)". */
  notes: string[];
};

export function describeAuthenticator(facts: AuthenticatorFacts): AuthenticatorDetails {
  const attested = Boolean(facts.attestationFormat && facts.attestationFormat !== "none");
  const notes: string[] = [];
  if (facts.synced) notes.push("Synced across your devices");
  else if (facts.kind === "security_key") notes.push("Stays on the key");
  // A key that can't check a PIN or fingerprint, or isn't stored on the key, only backs up another sign-in.
  if (facts.standalone === false) notes.push("Second step only");
  if (attested) notes.push(`Attested by the device (${facts.attestationFormat})`);
  return { kindLabel: facts.kind === "security_key" ? "Security key" : "Passkey", model: authenticatorModel(facts.aaguid), attested, notes };
}
