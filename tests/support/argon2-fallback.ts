import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

/**
 * Tests only: a stand-in for the native `argon2` module, used when this
 * machine can't load it (for example when an application control policy
 * blocks its prebuilt binary). tests/setup.ts uses the real module whenever it
 * loads. Same shape as the bits of argon2 Identity calls; hashes are
 * `$scrypt$<salt>$<hash>`, never accepted outside tests.
 */
const scrypt = promisify(scryptCallback) as (password: string, salt: Buffer, keylen: number) => Promise<Buffer>;

async function hash(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 32);
  return `$scrypt$${salt.toString("base64")}$${derived.toString("base64")}`;
}

async function verify(stored: string, password: string): Promise<boolean> {
  const [, kind, salt, expected] = stored.split("$");
  if (kind !== "scrypt" || !salt || !expected) throw new Error("Not a test hash");
  const derived = await scrypt(password, Buffer.from(salt, "base64"), 32);
  const want = Buffer.from(expected, "base64");
  return want.length === derived.length && timingSafeEqual(want, derived);
}

const fallback = { argon2d: 0, argon2i: 1, argon2id: 2, hash, verify };
export default fallback;
export { hash, verify };
