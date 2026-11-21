import {
  Env,
  Campaign,
  Recipient,
  HttpError,
  json,
  now,
  generateToken,
  requireAuth,
  verifyPassword,
  signJWT,
  dbFirst,
  dbAll,
  dbRun,
  imageUrl,
  themeImageUrl,
  giftImageUrl,
  sceneImageUrl,
  getTenantPlan,
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

// POST /api/admin/login { tenantSlug, username, password }
export async function postLogin(request: Request, env: Env): Promise<Response> {
  const { tenantSlug, username, password } = await bodyJson<{
    tenantSlug?: string;
    username?: string;
    password?: string;
  }>(request);
  if (!tenantSlug || !username || !password) {
    throw new HttpError(400, "All fields are required");
  }
  const tenant = await dbFirst<{
    id: string;
    slug: string;
    customer_name: string;
    admin_username: string;
    admin_password_hash: string;
    status: string;
  }>(env.DB, "SELECT * FROM tenants WHERE slug = ?", tenantSlug.toLowerCase().trim());
  // Always run a hash comparison to keep timing uniform
  const passwordOk = tenant
    ? await verifyPassword(password, tenant.admin_password_hash)
    : await verifyPassword(password, "pbkdf2$100000$AAAA$AAAA").catch(() => false);
  if (!tenant || !passwordOk || tenant.admin_username !== username.trim()) {
    throw new HttpError(401, "Invalid credentials");
  }
  if (tenant.status !== "active") throw new HttpError(403, "Account suspended");
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60; // 7 days
  const token = await signJWT({ tid: tenant.id, slug: tenant.slug, exp }, env.JWT_SECRET);
  return json({
    token,
    tenant: { slug: tenant.slug, customerName: tenant.customer_name },
  });
}

// GET /api/admin/me
export async function getMe(request: Request, env: Env): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const tenant = await dbFirst<{ slug: string; customer_name: string; plan: string }>(
    env.DB,
    "SELECT slug, customer_name, plan FROM tenants WHERE id = ?",
    tenantId,
  );
  const { planId, plan } = await getTenantPlan(env.DB, tenantId);
  return json({
    tenant: {
      ...tenant,
      planId,
      planLabel: plan.label,
      limits: {
        maxCampaigns: plan.maxCampaigns,
        maxRecipientsPerCampaign: plan.maxRecipientsPerCampaign,
      },
      watermark: plan.watermark,
    },
  });
}

// GET /api/admin/campaigns
export async function listCampaigns(request: Request, env: Env): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaigns = await dbAll<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE tenant_id = ? ORDER BY created_at DESC",
    tenantId,
  );
  // Attach recipient counts
  const counts = await dbAll<{ campaign_id: string; c: number }>(
    env.DB,
    "SELECT campaign_id, COUNT(*) as c FROM recipients WHERE campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?) GROUP BY campaign_id",
    tenantId,
  );
  const openedCounts = await dbAll<{ campaign_id: string; c: number }>(
    env.DB,
    "SELECT campaign_id, COUNT(*) as c FROM recipients WHERE campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?) AND opened_at IS NOT NULL GROUP BY campaign_id",
    tenantId,
  );
  const cMap = new Map(counts.map((r) => [r.campaign_id, r.c]));
  const oMap = new Map(openedCounts.map((r) => [r.campaign_id, r.c]));
  return json({
    campaigns: campaigns.map((c) => ({
      ...c,
      recipientCount: cMap.get(c.id) ?? 0,
      openedCount: oMap.get(c.id) ?? 0,
      imageUrl: imageUrl(env, request, c),
      themeImageUrl: themeImageUrl(env, request, c),
      giftImageUrl: giftImageUrl(env, request, c),
      sceneImageUrl: sceneImageUrl(env, request, c),
    })),
  });
}

// POST /api/admin/campaigns
export async function createCampaign(request: Request, env: Env): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);

  // Plan enforcement
  const { planId, plan } = await getTenantPlan(env.DB, tenantId);
  const count = await dbFirst<{ n: number }>(
    env.DB,
    "SELECT COUNT(*) as n FROM campaigns WHERE tenant_id = ?",
    tenantId,
  );
  const current = count?.n ?? 0;
  if (current >= plan.maxCampaigns) {
    throw new HttpError(
      403,
      `Campaign limit reached (${current}/${plan.maxCampaigns} on ${plan.label} plan). Contact the operator to upgrade.`,
    );
  }
  const body = await bodyJson<{
    type?: "wish" | "invitation";
    name?: string;
    senderName?: string;
    revealMessage?: string;
    eventTitle?: string;
    eventDescription?: string;
    eventDate?: string;
    eventTime?: string;
    eventLocation?: string;
    rsvpEnabled?: boolean;
  }>(request);
  if (body.type !== "wish" && body.type !== "invitation") {
    throw new HttpError(400, "type must be 'wish' or 'invitation'");
  }
  const name = (body.name ?? "").trim();
  const senderName = (body.senderName ?? "").trim();
  const revealMessage = (body.revealMessage ?? "").trim();
  if (!name || !senderName || !revealMessage) {
    throw new HttpError(400, "name, senderName, and revealMessage are required");
  }
  const id = crypto.randomUUID();
  const ts = now();
  const previewToken = generateToken();
  const sharedToken = body.type === "wish" ? null : null; // set on publish for wishes
  await dbRun(
    env.DB,
    `INSERT INTO campaigns (
      id, tenant_id, type, name, status, sender_name, reveal_message,
      event_title, event_description, event_date, event_time, event_location,
      rsvp_enabled, shared_token, preview_token, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id,
    tenantId,
    body.type,
    name,
    senderName,
    revealMessage,
    body.eventTitle ?? null,
    body.eventDescription ?? null,
    body.eventDate ?? null,
    body.eventTime ?? null,
    body.eventLocation ?? null,
    body.rsvpEnabled ? 1 : 0,
    sharedToken,
    previewToken,
    ts,
    ts,
  );
  const campaign = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", id);
  return json({ campaign, previewToken });
}

// GET /api/admin/campaigns/:id
export async function getCampaign(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");
  return json({
    campaign, imageUrl: imageUrl(env, request, campaign), themeImageUrl: themeImageUrl(env, request, campaign), giftImageUrl: giftImageUrl(env, request, campaign),
    sceneImageUrl: sceneImageUrl(env, request, campaign)
  });
}

// PATCH /api/admin/campaigns/:id
export async function updateCampaign(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const existing = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!existing) throw new HttpError(404, "Campaign not found");

  const body = await bodyJson<Record<string, unknown>>(request);
  const fields: string[] = [];
  const params: unknown[] = [];
  const setField = (col: string, val: unknown) => {
    if (val === undefined) return;
    fields.push(`${col} = ?`);
    params.push(val);
  };
  setField("name", typeof body.name === "string" ? body.name.trim() : undefined);
  setField("sender_name", typeof body.senderName === "string" ? body.senderName.trim() : undefined);
  setField(
    "reveal_message",
    typeof body.revealMessage === "string" ? body.revealMessage.trim() : undefined,
  );
  setField("event_title", typeof body.eventTitle === "string" ? body.eventTitle : undefined);
  setField(
    "event_description",
    typeof body.eventDescription === "string" ? body.eventDescription : undefined,
  );
  setField("event_date", typeof body.eventDate === "string" ? body.eventDate : undefined);
  setField("event_time", typeof body.eventTime === "string" ? body.eventTime : undefined);
  setField(
    "event_location",
    typeof body.eventLocation === "string" ? body.eventLocation : undefined,
  );
  if (typeof body.rsvpEnabled === "boolean") {
    fields.push("rsvp_enabled = ?");
    params.push(body.rsvpEnabled ? 1 : 0);
  }
  if (fields.length === 0) throw new HttpError(400, "No fields to update");
  fields.push("updated_at = ?");
  params.push(now());
  params.push(campaignId, tenantId);
  await dbRun(
    env.DB,
    `UPDATE campaigns SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`,
    ...params,
  );
  const campaign = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({
    campaign, imageUrl: imageUrl(env, request, campaign!), themeImageUrl: themeImageUrl(env, request, campaign!), giftImageUrl: giftImageUrl(env, request, campaign!),
    sceneImageUrl: sceneImageUrl(env, request, campaign!)
  });
}

// DELETE /api/admin/campaigns/:id
export async function deleteCampaign(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const existing = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!existing) throw new HttpError(404, "Campaign not found");
  if (existing.image_key) {
    await env.IMAGES.delete(existing.image_key).catch(() => { });
  }
  if (existing.theme_image_key) {
    await env.IMAGES.delete(existing.theme_image_key).catch(() => { });
  }
  if (existing.gift_image_key) {                                     // NEW
    await env.IMAGES.delete(existing.gift_image_key).catch(() => { }); // NEW
  }                                                                  // NEW
  if (existing.scene_image_key) {                                    // NEW
    await env.IMAGES.delete(existing.scene_image_key).catch(() => { }); // NEW
  }
  await dbRun(env.DB, "DELETE FROM campaigns WHERE id = ? AND tenant_id = ?", campaignId, tenantId);
  return json({ ok: true });
}

// POST /api/admin/campaigns/:id/publish
export async function publishCampaign(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");
  if (!campaign.image_key) throw new HttpError(400, "Upload a scratch image before publishing");

  let sharedToken = campaign.shared_token;
  if (campaign.type === "wish" && !sharedToken) {
    sharedToken = generateToken();
  }
  await dbRun(
    env.DB,
    "UPDATE campaigns SET status = 'published', shared_token = ?, updated_at = ? WHERE id = ?",
    sharedToken,
    now(),
    campaignId,
  );
  const updated = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({ campaign: updated, sharedToken });
}

// POST /api/admin/campaigns/:id/unpublish
export async function unpublishCampaign(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  await dbRun(
    env.DB,
    "UPDATE campaigns SET status = 'draft', updated_at = ? WHERE id = ? AND tenant_id = ?",
    now(),
    campaignId,
    tenantId,
  );
  return json({ ok: true });
}

// POST /api/admin/campaigns/:id/image (multipart, field "image")
export async function uploadCampaignImage(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");

  const form = await request.formData();
  const raw = form.get("image");
  // FormData entries are string | File. Strings happen when a text field
  // is submitted with the same name, so reject them explicitly.
  if (raw === null || typeof raw === "string") {
    throw new HttpError(400, "Missing 'image' file");
  }
  const file = raw as unknown as {
    size: number;
    type: string;
    arrayBuffer(): Promise<ArrayBuffer>;
  };
  if (file.size > 5 * 1024 * 1024) throw new HttpError(413, "Image must be ≤5 MB");
  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.type)) throw new HttpError(400, "Only JPG, PNG, or WebP");
  const ext = file.type === "image/jpeg" ? "jpg" : file.type.split("/")[1];
  const ts = now();
  const key = `tenants/${tenantId}/campaigns/${campaignId}/${ts}.${ext}`;
  await env.IMAGES.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type },
  });
  if (campaign.image_key) {
    await env.IMAGES.delete(campaign.image_key).catch(() => { });
  }
  await dbRun(
    env.DB,
    "UPDATE campaigns SET image_key = ?, image_content_type = ?, updated_at = ? WHERE id = ?",
    key,
    file.type,
    ts,
    campaignId,
  );
  const updated = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({ campaign: updated, imageUrl: imageUrl(env, request, updated!) });
}

// GET /api/admin/campaigns/:id/recipients
export async function listRecipients(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT id FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");
  const recipients = await dbAll<Recipient>(
    env.DB,
    "SELECT * FROM recipients WHERE campaign_id = ? ORDER BY created_at DESC",
    campaignId,
  );
  return json({ recipients });
}

// POST /api/admin/campaigns/:id/recipients { names: string[] } or { name: string }
export async function addRecipients(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");
  if (campaign.type !== "invitation") {
    throw new HttpError(400, "Recipients are only available for invitation campaigns");
  }

  const body = await bodyJson<{ name?: string; names?: string[] }>(request);
  const incoming = body.names ?? (body.name ? [body.name] : []);
  const cleaned = incoming.map((n) => n.trim()).filter((n) => n.length > 0);
  if (cleaned.length === 0) throw new HttpError(400, "No names provided");

  // Dedupe against existing (within this request AND against the DB)
  const existing = await dbAll<{ lower_name: string }>(
    env.DB,
    "SELECT LOWER(name) AS lower_name FROM recipients WHERE campaign_id = ?",
    campaignId,
  );
  const existingSet = new Set(existing.map((r) => r.lower_name));
  const toAdd: string[] = [];
  const skipped: string[] = [];
  for (const name of cleaned) {
    if (existingSet.has(name.toLowerCase())) {
      skipped.push(name);
    } else {
      existingSet.add(name.toLowerCase());
      toAdd.push(name);
    }
  }

  // Plan enforcement — check AFTER dedupe so duplicates don't consume quota.
  // A user re-pasting a list of 20 names where 18 are already added
  // only needs 2 slots, not 20.
  if (toAdd.length > 0) {
    const { plan } = await getTenantPlan(env.DB, tenantId);
    const existingCount = existing.length;
    const remaining = plan.maxRecipientsPerCampaign - existingCount;

    if (toAdd.length > remaining) {
      const limitLabel =
        plan.maxRecipientsPerCampaign >= 1_000_000
          ? "unlimited"
          : String(plan.maxRecipientsPerCampaign);
      const msg =
        remaining <= 0
          ? `Recipient limit reached (${existingCount}/${limitLabel} on ${plan.label} plan). Contact the operator to upgrade.`
          : `Only ${remaining} recipient slot${remaining === 1 ? "" : "s"} left (${existingCount}/${limitLabel} on ${plan.label} plan). You tried to add ${toAdd.length} new name${toAdd.length === 1 ? "" : "s"}.`;
      throw new HttpError(403, msg);
    }
  }

  // Insert new recipients in chunks of 25 (D1 bind parameter limit)
  const CHUNK = 25;
  const ts = now();
  for (let i = 0; i < toAdd.length; i += CHUNK) {
    const chunk = toAdd.slice(i, i + CHUNK);
    const placeholders = chunk.map(() => "(?, ?, ?, ?, ?)").join(",");
    const params: unknown[] = [];
    for (const name of chunk) {
      params.push(crypto.randomUUID(), campaignId, name, generateToken(), ts);
    }
    await dbRun(
      env.DB,
      `INSERT INTO recipients (id, campaign_id, name, token, created_at) VALUES ${placeholders}`,
      ...params,
    );
  }

  // Return the newly-created recipients so the UI can render them immediately.
  const added =
    toAdd.length === 0
      ? []
      : await dbAll<Recipient>(
          env.DB,
          "SELECT * FROM recipients WHERE campaign_id = ? ORDER BY created_at DESC LIMIT ?",
          campaignId,
          toAdd.length,
        );

  return json({ added: added.length, skipped, recipients: added });
}

// PATCH /api/admin/recipients/:id { status: 'active'|'disabled' }
export async function updateRecipient(
  request: Request,
  env: Env,
  recipientId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const body = await bodyJson<{ status?: string }>(request);
  if (body.status !== "active" && body.status !== "disabled") {
    throw new HttpError(400, "status must be 'active' or 'disabled'");
  }
  const result = await env.DB.prepare(
    "UPDATE recipients SET status = ? WHERE id = ? AND campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?)",
  )
    .bind(body.status, recipientId, tenantId)
    .run();
  if (result.meta.changes === 0) throw new HttpError(404, "Recipient not found");
  return json({ ok: true });
}

// DELETE /api/admin/recipients/:id
export async function deleteRecipient(
  request: Request,
  env: Env,
  recipientId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  await dbRun(
    env.DB,
    "DELETE FROM recipients WHERE id = ? AND campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?)",
    recipientId,
    tenantId,
  );
  return json({ ok: true });
}

// POST /api/admin/recipients/:id/regenerate
export async function regenerateRecipientToken(
  request: Request,
  env: Env,
  recipientId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const newToken = generateToken();
  const result = await env.DB.prepare(
    "UPDATE recipients SET token = ? WHERE id = ? AND campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?)",
  )
    .bind(newToken, recipientId, tenantId)
    .run();
  if (result.meta.changes === 0) throw new HttpError(404, "Recipient not found");
  return json({ token: newToken });
}

// GET /api/admin/stats
export async function getStats(request: Request, env: Env): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const { planId, plan } = await getTenantPlan(env.DB, tenantId);
  const totals = await dbFirst<{ total: number; published: number }>(
    env.DB,
    "SELECT COUNT(*) as total, SUM(CASE WHEN status = 'published' THEN 1 ELSE 0 END) as published FROM campaigns WHERE tenant_id = ?",
    tenantId,
  );
  const recip = await dbFirst<{ total: number; opened: number; scratched: number; rsvps: number }>(
    env.DB,
    `SELECT
       COUNT(*) as total,
       SUM(CASE WHEN opened_at IS NOT NULL THEN 1 ELSE 0 END) as opened,
       SUM(CASE WHEN scratched_at IS NOT NULL THEN 1 ELSE 0 END) as scratched,
       SUM(CASE WHEN rsvped_at IS NOT NULL THEN 1 ELSE 0 END) as rsvps
     FROM recipients WHERE campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = ?)`,
    tenantId,
  );
  const wishOpens = await dbFirst<{ opens: number; scratches: number }>(
    env.DB,
    "SELECT SUM(open_count) as opens, SUM(scratch_count) as scratches FROM campaigns WHERE tenant_id = ?",
    tenantId,
  );
  const recentActivity = await dbAll<{
    id: string;
    campaign_id: string;
    event_type: string;
    created_at: number;
    campaign_name: string;
    recipient_name: string | null;
  }>(
    env.DB,
    `SELECT a.id, a.campaign_id, a.event_type, a.created_at,
            c.name as campaign_name, r.name as recipient_name
     FROM activity_log a
     LEFT JOIN campaigns c ON c.id = a.campaign_id
     LEFT JOIN recipients r ON r.id = a.recipient_id
     WHERE a.tenant_id = ?
     ORDER BY a.created_at DESC LIMIT 20`,
    tenantId,
  );
  return json({
    campaigns: {
      total: totals?.total ?? 0,
      published: totals?.published ?? 0,
    },
    recipients: {
      total: recip?.total ?? 0,
      opened: recip?.opened ?? 0,
      scratched: recip?.scratched ?? 0,
      rsvps: recip?.rsvps ?? 0,
    },
    wishes: {
      opens: wishOpens?.opens ?? 0,
      scratches: wishOpens?.scratches ?? 0,
    },
    recentActivity,
    plan: {
    id: planId,
    label: plan.label,
    maxCampaigns: plan.maxCampaigns,
    maxRecipientsPerCampaign: plan.maxRecipientsPerCampaign,
    watermark: plan.watermark,
    campaignsUsed: totals?.total ?? 0,
    campaignsRemaining: Math.max(0, plan.maxCampaigns - (totals?.total ?? 0)),
  },
  });
}

// POST /api/admin/campaigns/:id/theme-image  (multipart, field "image")
export async function uploadThemeImage(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");

  const form = await request.formData();
  const raw = form.get("image");
  if (raw === null || typeof raw === "string") throw new HttpError(400, "Missing 'image' file");
  const file = raw as unknown as { size: number; type: string; arrayBuffer(): Promise<ArrayBuffer> };

  if (file.size > 8 * 1024 * 1024) throw new HttpError(413, "Image must be ≤8 MB");
  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.type)) throw new HttpError(400, "Only JPG, PNG, or WebP");

  const ext = file.type === "image/jpeg" ? "jpg" : file.type.split("/")[1];
  const ts = now();
  const key = `tenants/${tenantId}/campaigns/${campaignId}/theme-${ts}.${ext}`;

  await env.IMAGES.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type },
  });
  if (campaign.theme_image_key) {
    await env.IMAGES.delete(campaign.theme_image_key).catch(() => { });
  }
  await dbRun(
    env.DB,
    "UPDATE campaigns SET theme_image_key = ?, theme_image_content_type = ?, updated_at = ? WHERE id = ?",
    key,
    file.type,
    ts,
    campaignId,
  );
  const updated = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({
    campaign: updated,
    themeImageUrl: themeImageUrl(env, request, updated!),
  });
}

// POST /api/admin/campaigns/:id/gift-image
export async function uploadGiftImage(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");

  const form = await request.formData();
  const raw = form.get("image");
  if (raw === null || typeof raw === "string") throw new HttpError(400, "Missing 'image' file");
  const file = raw as unknown as { size: number; type: string; arrayBuffer(): Promise<ArrayBuffer> };

  if (file.size > 8 * 1024 * 1024) throw new HttpError(413, "Image must be ≤8 MB");
  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.type)) throw new HttpError(400, "Only JPG, PNG, or WebP");

  const ext = file.type === "image/jpeg" ? "jpg" : file.type.split("/")[1];
  const ts = now();
  const key = `tenants/${tenantId}/campaigns/${campaignId}/gift-${ts}.${ext}`;
  await env.IMAGES.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type },
  });
  if (campaign.gift_image_key) {
    await env.IMAGES.delete(campaign.gift_image_key).catch(() => { });
  }
  await dbRun(
    env.DB,
    "UPDATE campaigns SET gift_image_key = ?, gift_image_content_type = ?, updated_at = ? WHERE id = ?",
    key,
    file.type,
    ts,
    campaignId,
  );
  const updated = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({
    campaign: updated,
    giftImageUrl: giftImageUrl(env, request, updated!),
  });
}

// POST /api/admin/campaigns/:id/scene-image
export async function uploadSceneImage(
  request: Request,
  env: Env,
  campaignId: string,
): Promise<Response> {
  const { tenantId } = await requireAuth(request, env);
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?",
    campaignId,
    tenantId,
  );
  if (!campaign) throw new HttpError(404, "Campaign not found");

  const form = await request.formData();
  const raw = form.get("image");
  if (raw === null || typeof raw === "string") throw new HttpError(400, "Missing 'image' file");
  const file = raw as unknown as { size: number; type: string; arrayBuffer(): Promise<ArrayBuffer> };

  if (file.size > 8 * 1024 * 1024) throw new HttpError(413, "Image must be ≤8 MB");
  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.type)) throw new HttpError(400, "Only JPG, PNG, or WebP");

  const ext = file.type === "image/jpeg" ? "jpg" : file.type.split("/")[1];
  const ts = now();
  const key = `tenants/${tenantId}/campaigns/${campaignId}/scene-${ts}.${ext}`;
  await env.IMAGES.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type },
  });
  if (campaign.scene_image_key) {
    await env.IMAGES.delete(campaign.scene_image_key).catch(() => { });
  }
  await dbRun(
    env.DB,
    "UPDATE campaigns SET scene_image_key = ?, scene_image_content_type = ?, updated_at = ? WHERE id = ?",
    key,
    file.type,
    ts,
    campaignId,
  );
  const updated = await dbFirst<Campaign>(env.DB, "SELECT * FROM campaigns WHERE id = ?", campaignId);
  return json({
    campaign: updated,
    sceneImageUrl: sceneImageUrl(env, request, updated!),
  });
}

