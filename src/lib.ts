// Shared types, crypto, auth, and DB helpers.

export interface Env {
  DB: D1Database;
  IMAGES: R2Bucket;
  JWT_SECRET: string;
  MASTER_SECRET: string;
  R2_PUBLIC_URL?: string;
}

export interface Tenant {
  id: string;
  slug: string;
  customer_name: string;
  admin_username: string;
  admin_password_hash: string;
  status: "active" | "suspended";
  created_at: number;
  updated_at: number;
}

export interface Campaign {
  id: string;
  tenant_id: string;
  type: "wish" | "invitation";
  name: string;
  status: "draft" | "published";
  sender_name: string;
  reveal_message: string;
  image_key: string | null;
  image_content_type: string | null;
  event_title: string | null;
  event_description: string | null;
  event_date: string | null;
  event_time: string | null;
  event_location: string | null;
  rsvp_enabled: number;
  shared_token: string | null;
  preview_token: string;
  open_count: number;
  scratch_count: number;
  created_at: number;
  updated_at: number;
}

export interface Recipient {
  id: string;
  campaign_id: string;
  name: string;
  token: string;
  status: "active" | "disabled";
  opened_at: number | null;
  scratched_at: number | null;
  rsvp_status: "attending" | "not_attending" | null;
  rsvp_guest_count: number | null;
  rsvp_message: string | null;
  rsvped_at: number | null;
  created_at: number;
}

// ---------- Errors ----------
export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// ---------- Responses ----------
export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Master-Secret",
  "Access-Control-Max-Age": "86400",
};

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

export function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// ---------- Encoding ----------
export function base64urlEncode(input: ArrayBuffer | Uint8Array | string): string {
  let bytes: Uint8Array;
  if (typeof input === "string") bytes = new TextEncoder().encode(input);
  else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
  else bytes = input;
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- Tokens ----------
export function generateToken(bytes = 24): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

// ---------- JWT (HS256) ----------
async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signJWT(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64urlEncode(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${base64urlEncode(sig)}`;
}

export async function verifyJWT(
  token: string,
  secret: string,
): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const key = await hmacKey(secret);
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    base64urlDecode(s),
    new TextEncoder().encode(`${h}.${b}`),
  );
  if (!ok) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(b)));
    if (typeof payload.exp === "number" && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- Passwords (PBKDF2-SHA256, 100k iters) ----------
const PBKDF2_ITERATIONS = 100_000;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64urlEncode(salt)}$${base64urlEncode(bits)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = base64urlDecode(parts[2]);
  const expected = parts[3];
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256,
  );
  return constantTimeEqual(base64urlEncode(bits), expected);
}

// ---------- Auth guards ----------
export async function requireAuth(
  request: Request,
  env: Env,
): Promise<{ tenantId: string; slug: string }> {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) throw new HttpError(401, "Unauthorized");
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload || typeof payload.tid !== "string" || typeof payload.slug !== "string") {
    throw new HttpError(401, "Invalid or expired session");
  }
  const tenant = await env.DB.prepare(
    "SELECT id, slug, status FROM tenants WHERE id = ?",
  )
    .bind(payload.tid)
    .first<{ id: string; slug: string; status: string }>();
  if (!tenant) throw new HttpError(401, "Tenant not found");
  if (tenant.status !== "active") throw new HttpError(403, "Tenant suspended");
  return { tenantId: tenant.id, slug: tenant.slug };
}

export function requireMaster(request: Request, env: Env): void {
  const provided = request.headers.get("X-Master-Secret");
  if (!provided || !constantTimeEqual(provided, env.MASTER_SECRET)) {
    throw new HttpError(401, "Master secret invalid");
  }
}

// ---------- Image URL ----------
export function imageUrl(env: Env, request: Request, campaign: Campaign): string | null {
  if (!campaign.image_key) return null;
  if (env.R2_PUBLIC_URL) return `${env.R2_PUBLIC_URL}/${campaign.image_key}`;
  const origin = new URL(request.url).origin;
  return `${origin}/api/image/${campaign.id}`;
}

// ---------- Time ----------
export function now(): number {
  return Date.now();
}

// ---------- DB helpers ----------
export async function dbFirst<T>(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<T | null> {
  return await db.prepare(sql).bind(...params).first<T>();
}

export async function dbAll<T>(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<T[]> {
  const res = await db.prepare(sql).bind(...params).all<T>();
  return res.results ?? [];
}

export async function dbRun(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<void> {
  await db.prepare(sql).bind(...params).run();
}