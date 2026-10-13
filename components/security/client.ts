"use client";
import { getCsrf } from "@/lib/auth/csrf-client";

export async function securityRequest<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": await getCsrf() }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message ?? "Security request failed");
  return data as T;
}
