type Bucket = {
  count: number;
  resetAt: number;
  lockedUntil?: number;
};

const buckets = new Map<string, Bucket>();

function now(): number {
  return Date.now();
}

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
};

export function checkRateLimit(
  key: string,
  max: number,
  windowSeconds: number,
): RateLimitResult {
  const current = now();
  const existing = buckets.get(key);

  if (!existing || existing.resetAt <= current) {
    buckets.set(key, {
      count: 1,
      resetAt: current + windowSeconds * 1000,
    });
    return {
      allowed: true,
      remaining: max - 1,
      retryAfterSeconds: 0,
    };
  }

  if (existing.count >= max) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil((existing.resetAt - current) / 1000),
    };
  }

  existing.count += 1;
  buckets.set(key, existing);
  return {
    allowed: true,
    remaining: Math.max(0, max - existing.count),
    retryAfterSeconds: 0,
  };
}

export type LoginAttemptResult = {
  allowed: boolean;
  remainingAttempts: number;
  retryAfterSeconds: number;
};

export function checkLoginAttempts(
  key: string,
  maxAttempts: number,
  windowSeconds: number,
  lockoutSeconds: number,
): LoginAttemptResult {
  const current = now();
  const existing = buckets.get(`login:${key}`);

  if (existing?.lockedUntil && existing.lockedUntil > current) {
    return {
      allowed: false,
      remainingAttempts: 0,
      retryAfterSeconds: Math.ceil((existing.lockedUntil - current) / 1000),
    };
  }

  if (!existing || existing.resetAt <= current) {
    buckets.set(`login:${key}`, {
      count: 0,
      resetAt: current + windowSeconds * 1000,
    });
    return {
      allowed: true,
      remainingAttempts: maxAttempts,
      retryAfterSeconds: 0,
    };
  }

  if (existing.count >= maxAttempts) {
    existing.lockedUntil = current + lockoutSeconds * 1000;
    buckets.set(`login:${key}`, existing);
    return {
      allowed: false,
      remainingAttempts: 0,
      retryAfterSeconds: lockoutSeconds,
    };
  }

  return {
    allowed: true,
    remainingAttempts: maxAttempts - existing.count,
    retryAfterSeconds: 0,
  };
}

export function recordFailedLogin(
  key: string,
  maxAttempts: number,
  windowSeconds: number,
  lockoutSeconds: number,
): LoginAttemptResult {
  const current = now();
  const mapKey = `login:${key}`;
  const existing = buckets.get(mapKey);

  if (!existing || existing.resetAt <= current) {
    buckets.set(mapKey, {
      count: 1,
      resetAt: current + windowSeconds * 1000,
    });
    return {
      allowed: true,
      remainingAttempts: maxAttempts - 1,
      retryAfterSeconds: 0,
    };
  }

  existing.count += 1;
  if (existing.count >= maxAttempts) {
    existing.lockedUntil = current + lockoutSeconds * 1000;
  }
  buckets.set(mapKey, existing);

  return {
    allowed: existing.count < maxAttempts,
    remainingAttempts: Math.max(0, maxAttempts - existing.count),
    retryAfterSeconds: existing.lockedUntil
      ? Math.ceil((existing.lockedUntil - current) / 1000)
      : 0,
  };
}

export function clearLoginAttempts(key: string): void {
  buckets.delete(`login:${key}`);
}

export function checkCooldown(
  key: string,
  cooldownSeconds: number,
): RateLimitResult {
  return checkRateLimit(`cooldown:${key}`, 1, cooldownSeconds);
}

export function resetRateLimitStore(): void {
  buckets.clear();
}

export function getClientIp(request: Request): string {
  const forwarded = request.headers.get(process.env.TRUSTED_CLIENT_IP_HEADER ?? "x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",").at(-1)?.trim() || "unknown";
  }
  return request.headers.get("x-real-ip") || "unknown";
}
