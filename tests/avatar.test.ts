import { describe, expect, it } from "vitest";
import { checkAvatar, MAX_AVATAR_BYTES, sniffImage } from "@/lib/account/avatar-image";
import { readAvatar, removeAvatar, setAvatar } from "@/lib/account/avatar";
import { deleteUserAccount } from "@/lib/account/delete-account";
import { listEvents } from "@/lib/audit/event-log";
import { updateProfileSchema } from "@/lib/validation/schemas";
import { GET as serveAvatar } from "@/app/api/avatars/[userId]/[hash]/route";
import { Avatar } from "@/models/Avatar";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

/** A PNG header with the given size (enough for sniffing; the rest is padding). */
function png(width: number, height: number, padding = 64) {
  const bytes = Buffer.alloc(24 + padding);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes, 0);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12, "ascii");
  bytes.writeUInt32BE(width, 16);
  bytes.writeUInt32BE(height, 20);
  bytes[30] = width % 251; // so different sizes hash differently
  return bytes;
}

function jpeg(width: number, height: number) {
  return Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x4a, 0x46, 0xff, 0xc0, 0x00, 0x11, 0x08, height >> 8, height & 0xff, width >> 8, width & 0xff, 0x03, 0, 0, 0, 0]);
}

function webpExtended(width: number, height: number) {
  const bytes = Buffer.alloc(40);
  bytes.write("RIFF", 0, "ascii");
  bytes.writeUInt32LE(32, 4);
  bytes.write("WEBPVP8X", 8, "ascii");
  bytes.writeUIntLE(width - 1, 24, 3);
  bytes.writeUIntLE(height - 1, 27, 3);
  return bytes;
}

describe("photo checks", () => {
  it("tells PNG, JPEG and WebP apart by their bytes and reads their size", () => {
    expect(sniffImage(png(256, 200))).toEqual({ type: "image/png", width: 256, height: 200 });
    expect(sniffImage(jpeg(640, 480))).toEqual({ type: "image/jpeg", width: 640, height: 480 });
    expect(sniffImage(webpExtended(300, 300))).toEqual({ type: "image/webp", width: 300, height: 300 });
    expect(sniffImage(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))).toBeNull();
    expect(sniffImage(Buffer.from("GIF89a....."))).toBeNull();
  });

  it("refuses what isn't a photo we keep", () => {
    expect(checkAvatar(png(256, 256), "image/png")).toMatchObject({ ok: true });
    expect(checkAvatar(Buffer.from("<svg/>"), "image/svg+xml")).toEqual({ ok: false, error: "Use a PNG, JPEG or WebP photo" });
    expect(checkAvatar(png(256, 256), "image/jpeg")).toEqual({ ok: false, error: "The photo isn't the kind of file it says it is" });
    expect(checkAvatar(png(4000, 4000), "image/png")).toMatchObject({ ok: false, error: "Photos can be up to 1024×1024" });
    expect(checkAvatar(png(8, 8), "image/png")).toMatchObject({ ok: false });
    expect(checkAvatar(png(256, 256, MAX_AVATAR_BYTES), "image/png")).toMatchObject({ ok: false, error: "Photos can be up to 512 KB" });
    expect(checkAvatar(Buffer.alloc(0), "image/png")).toMatchObject({ ok: false });
  });

  it("only lets the profile form remove a photo, not point it somewhere", () => {
    expect(updateProfileSchema.safeParse({ avatarUrl: null }).success).toBe(true);
    expect(updateProfileSchema.safeParse({ avatarUrl: "https://tracker.example/pixel.png" }).success).toBe(false);
  });
});

describe("profile photos", () => {
  it("keeps an upload, serves it at an address that changes with it, and removes it", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const first = png(256, 256);
    const { avatarUrl } = await setAvatar(id, first, "image/png", { ipAddress: "203.0.113.7" });
    expect(avatarUrl).toMatch(new RegExp(`^http://localhost:3000/api/avatars/${id}/[a-f0-9]{24}$`));
    expect((await User.findById(id).lean())!.avatarUrl).toBe(avatarUrl);
    const firstHash = avatarUrl.split("/").at(-1)!;

    const response = await serveAvatar(new Request(avatarUrl), { params: Promise.resolve({ userId: id, hash: firstHash }) });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/png");
    expect(response.headers.get("cache-control")).toContain("immutable");
    expect(response.headers.get("content-security-policy")).toContain("sandbox");
    expect(Buffer.from(await response.arrayBuffer()).equals(first)).toBe(true);

    // A new photo: a new address, and the old one stops working.
    const second = await setAvatar(id, jpeg(300, 300), "image/jpeg");
    expect(second.avatarUrl).not.toBe(avatarUrl);
    expect(await readAvatar(id, firstHash)).toBeNull();
    expect(await Avatar.countDocuments({ userId: user._id })).toBe(1);

    await removeAvatar(id);
    expect((await User.findById(id).lean())!.avatarUrl).toBeNull();
    expect(await Avatar.countDocuments()).toBe(0);
    const missing = await serveAvatar(new Request(avatarUrl), { params: Promise.resolve({ userId: id, hash: "0".repeat(24) }) });
    expect(missing.status).toBe(404);

    const events = (await listEvents({ action: "account.profile_updated" })).events;
    expect(events.map((e) => e.data)).toEqual([{ fields: ["avatarUrl"], removed: true }, { fields: ["avatarUrl"], uploaded: true }, { fields: ["avatarUrl"], uploaded: true }]);
  });

  it("refuses a bad upload without changing anything", async () => {
    const { user } = await createTestUser();
    await expect(setAvatar(String(user._id), Buffer.from("<svg/>"), "image/svg+xml")).rejects.toMatchObject({ code: "invalid_image" });
    expect((await User.findById(user._id).lean())!.avatarUrl).toBeNull();
  });

  it("goes with the account when it's deleted", async () => {
    const { user } = await createTestUser();
    await setAvatar(String(user._id), png(64, 64), "image/png");
    await deleteUserAccount(user._id);
    expect(await Avatar.countDocuments()).toBe(0);
  });
});
