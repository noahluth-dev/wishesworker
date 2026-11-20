import {
  Env,
  HttpError,
  json,
  now,
  hashPassword,
  requireMaster,
  dbFirst,
  dbAll,
  dbRun,
} from "./lib";

async function bodyJson<T = Record<string, unknown>>(request: Request): Promise<T> {
  const text = await request.text();
  if (!text.trim()) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])?$/;

// POST /api/master/provision
export async function postProvision(request: Request, env: Env): Promise<Response> {
  requireMaster(request, env);
  const { slug, customerName, adminUsername, adminPassword } = await bodyJson<{
    slug?: string;
    customerName?: string;
    adminUsername?: string;
    adminPassword?: string;
  }>(request);
  if (!slug || !customerName || !adminUsername || !adminPassword) {
    throw new HttpError(400, "All fields are required");
  }
  const cleanSlug = slug.toLowerCase().trim();
  if (!SLUG_RE.test(cleanSlug)) {
    throw new HttpError(400, "Slug must be 3-32 chars: a-z, 0-9, hyphens (no leading/trailing hyphen)");
  }
  if (adminPassword.length < 8) {
    throw new HttpError(400, "Admin password must be at least 8 characters");
  }
  const exists = await dbFirst<{ id: string }>(
    env.DB,
    "SELECT id FROM tenants WHERE slug = ?",
    cleanSlug,
  );
  if (exists) throw new HttpError(409, "Slug already taken");

  const id = crypto.randomUUID();
  const ts = now();
  const hash = await hashPassword(adminPassword);
  await dbRun(
    env.DB,
    "INSERT INTO tenants (id, slug, customer_name, admin_username, admin_password_hash, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
    id,
    cleanSlug,
    customerName.trim(),
    adminUsername.trim(),
    hash,
    ts,
    ts,
  );

  const origin = new URL(request.url).origin;
  return json({
    tenant: { id, slug: cleanSlug, customerName: customerName.trim() },
    config: { apiUrl: origin, tenantSlug: cleanSlug },
  });
}

// GET /api/master/tenants
export async function listTenants(request: Request, env: Env): Promise<Response> {
  requireMaster(request, env);
  const tenants = await dbAll<{
    id: string;
    slug: string;
    customer_name: string;
    admin_username: string;
    status: string;
    created_at: number;
    campaign_count: number;
  }>(
    env.DB,
    `SELECT t.id, t.slug, t.customer_name, t.admin_username, t.status, t.created_at,
            (SELECT COUNT(*) FROM campaigns c WHERE c.tenant_id = t.id) as campaign_count
     FROM tenants t ORDER BY t.created_at DESC`,
  );
  return json({ tenants });
}

// DELETE /api/master/tenants/:slug
export async function deleteTenant(
  request: Request,
  env: Env,
  slug: string,
): Promise<Response> {
  requireMaster(request, env);
  const tenant = await dbFirst<{ id: string }>(
    env.DB,
    "SELECT id FROM tenants WHERE slug = ?",
    slug,
  );
  if (!tenant) throw new HttpError(404, "Tenant not found");

  // Delete R2 images
  const keys = await dbAll<{ image_key: string | null }>(
    env.DB,
    "SELECT image_key FROM campaigns WHERE tenant_id = ? AND image_key IS NOT NULL",
    tenant.id,
  );
  await Promise.all(keys.map((k) => env.IMAGES.delete(k.image_key!).catch(() => {})));

  // Cascade deletes handle campaigns, recipients, activity
  await dbRun(env.DB, "DELETE FROM tenants WHERE id = ?", tenant.id);
  return json({ ok: true });
}

// POST /api/master/tenants/:slug/reset-password { password }
export async function resetTenantPassword(
  request: Request,
  env: Env,
  slug: string,
): Promise<Response> {
  requireMaster(request, env);
  const { password } = await bodyJson<{ password?: string }>(request);
  if (!password || password.length < 8) {
    throw new HttpError(400, "Password must be at least 8 characters");
  }
  const tenant = await dbFirst<{ id: string }>(
    env.DB,
    "SELECT id FROM tenants WHERE slug = ?",
    slug,
  );
  if (!tenant) throw new HttpError(404, "Tenant not found");
  const hash = await hashPassword(password);
  await dbRun(
    env.DB,
    "UPDATE tenants SET admin_password_hash = ?, updated_at = ? WHERE id = ?",
    hash,
    now(),
    tenant.id,
  );
  return json({ ok: true });
}