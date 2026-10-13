import { exportJWK, importPKCS8, importSPKI, type JWK } from "jose";
import { getEnv } from "@/lib/config/env";

type SigningKey = Awaited<ReturnType<typeof importPKCS8>>;

type KeySet = {
  privateKey: SigningKey;
  publicKey: SigningKey;
  publicJwk: JWK;
  kid: string;
};

let cached: KeySet | null = null;

export async function getSigningKeys(): Promise<KeySet> {
  if (cached) {
    return cached;
  }

  const env = getEnv();
  const privateKey = await importPKCS8(env.JWT_PRIVATE_KEY, "RS256");
  const publicKey = await importSPKI(env.JWT_PUBLIC_KEY, "RS256");
  const publicJwk = await exportJWK(publicKey);
  if (!publicJwk.n || Buffer.from(publicJwk.n, "base64url").length < 256) throw new Error("JWT signing requires an RSA key of at least 2048 bits");
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  publicJwk.kid = env.JWT_KEY_ID;

  cached = {
    privateKey,
    publicKey,
    publicJwk,
    kid: env.JWT_KEY_ID,
  };
  return cached;
}

export function resetSigningKeyCache(): void {
  cached = null;
}

export async function getJwks(): Promise<{ keys: JWK[] }> {
  const keys = await getSigningKeys();
  return { keys: [keys.publicJwk] };
}
