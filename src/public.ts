import {
  Env,
  Campaign,
  Recipient,
  HttpError,
  json,
  now,
  dbFirst,
  dbRun,
  imageUrl,
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

interface TokenLookup {
  campaign: Campaign;
  recipient: Recipient | null;
  isPreview: boolean;
}

async function resolveToken(env: Env, token: string): Promise<TokenLookup> {
  // 1) Try recipient token (invitation)
  const rec = await dbFirst<Recipient>(
    env.DB,
    "SELECT * FROM recipients WHERE token = ?",
    token,
  );
  if (rec) {
    const campaign = await dbFirst<Campaign>(
      env.DB,
      "SELECT * FROM campaigns WHERE id = ?",
      rec.campaign_id,
    );
    if (!campaign) throw new HttpError(404, "Campaign not found");
    if (campaign.status !== "published")
      throw new HttpError(404, "This invitation is not available.");
    if (rec.status !== "active")
      throw new HttpError(404, "This invitation has been disabled.");
    return { campaign, recipient: rec, isPreview: false };
  }
  // 2) Try shared token (published wish)
  const shared = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE shared_token = ?",
    token,
  );
  if (shared) {
    if (shared.status !== "published")
      throw new HttpError(404, "This wish is not available.");
    return { campaign: shared, recipient: null, isPreview: false };
  }
  // 3) Try preview token (draft preview)
  const preview = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE preview_token = ?",
    token,
  );
  if (preview) {
    return { campaign: preview, recipient: null, isPreview: true };
  }
  throw new HttpError(404, "This link is not valid.");
}

function shapeExperience(
  env: Env,
  request: Request,
  lookup: TokenLookup,
  token: string,
) {
  const { campaign, recipient, isPreview } = lookup;
  const isInvitation = campaign.type === "invitation";
  return {
    campaignId: campaign.id,
    type: campaign.type,
    isPreview,
    senderName: campaign.sender_name,
    revealMessage: campaign.reveal_message,
    imageUrl: imageUrl(env, request, campaign),
    recipientName: recipient?.name ?? null,
    event:
      isInvitation && campaign.event_title
        ? {
            title: campaign.event_title,
            description: campaign.event_description,
            date: campaign.event_date,
            time: campaign.event_time,
            location: campaign.event_location,
          }
        : null,
    rsvpEnabled: isInvitation && campaign.rsvp_enabled === 1,
    rsvpState:
      recipient && recipient.rsvped_at
        ? {
            submitted: true,
            status: recipient.rsvp_status,
            guestCount: recipient.rsvp_guest_count,
            message: recipient.rsvp_message,
          }
        : { submitted: false },
    token,
  };
}

// POST /api/public/experience { token }
export async function postExperience(request: Request, env: Env): Promise<Response> {
  const { token } = await bodyJson<{ token?: string }>(request);
  if (!token) throw new HttpError(400, "Missing token");
  const lookup = await resolveToken(env, token);
  return json(shapeExperience(env, request, lookup, token));
}

// POST /api/public/mark-opened { token }
export async function postMarkOpened(request: Request, env: Env): Promise<Response> {
  const { token } = await bodyJson<{ token?: string }>(request);
  if (!token) throw new HttpError(400, "Missing token");
  const { campaign, recipient } = await resolveToken(env, token);
  const ts = now();

  if (recipient) {
    if (recipient.opened_at === null) {
      await dbRun(
        env.DB,
        "UPDATE recipients SET opened_at = ? WHERE id = ? AND opened_at IS NULL",
        ts,
        recipient.id,
      );
      await dbRun(
        env.DB,
        "INSERT INTO activity_log (id, tenant_id, campaign_id, recipient_id, event_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        crypto.randomUUID(),
        campaign.tenant_id,
        campaign.id,
        recipient.id,
        "opened",
        ts,
      );
    }
  } else {
    await dbRun(
      env.DB,
      "UPDATE campaigns SET open_count = open_count + 1 WHERE id = ?",
      campaign.id,
    );
    await dbRun(
      env.DB,
      "INSERT INTO activity_log (id, tenant_id, campaign_id, recipient_id, event_type, created_at) VALUES (?, ?, ?, NULL, ?, ?)",
      crypto.randomUUID(),
      campaign.tenant_id,
      campaign.id,
      "opened",
      ts,
    );
  }
  return json({ ok: true });
}

// POST /api/public/mark-scratched { token }
export async function postMarkScratched(request: Request, env: Env): Promise<Response> {
  const { token } = await bodyJson<{ token?: string }>(request);
  if (!token) throw new HttpError(400, "Missing token");
  const { campaign, recipient } = await resolveToken(env, token);
  const ts = now();

  if (recipient) {
    if (recipient.scratched_at === null) {
      await dbRun(
        env.DB,
        "UPDATE recipients SET scratched_at = ?, opened_at = COALESCE(opened_at, ?) WHERE id = ? AND scratched_at IS NULL",
        ts,
        ts,
        recipient.id,
      );
      await dbRun(
        env.DB,
        "INSERT INTO activity_log (id, tenant_id, campaign_id, recipient_id, event_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        crypto.randomUUID(),
        campaign.tenant_id,
        campaign.id,
        recipient.id,
        "scratched",
        ts,
      );
    }
  } else {
    await dbRun(
      env.DB,
      "UPDATE campaigns SET scratch_count = scratch_count + 1 WHERE id = ?",
      campaign.id,
    );
    await dbRun(
      env.DB,
      "INSERT INTO activity_log (id, tenant_id, campaign_id, recipient_id, event_type, created_at) VALUES (?, ?, ?, NULL, ?, ?)",
      crypto.randomUUID(),
      campaign.tenant_id,
      campaign.id,
      "scratched",
      ts,
    );
  }
  return json({ ok: true });
}

// POST /api/public/rsvp { token, status, guestCount?, message? }
export async function postRsvp(request: Request, env: Env): Promise<Response> {
  const body = await bodyJson<{
    token?: string;
    status?: string;
    guestCount?: number;
    message?: string;
  }>(request);
  const { token, status, guestCount, message } = body;
  if (!token) throw new HttpError(400, "Missing token");
  if (status !== "attending" && status !== "not_attending") {
    throw new HttpError(400, "Invalid RSVP status");
  }
  const { campaign, recipient } = await resolveToken(env, token);
  if (!recipient) throw new HttpError(400, "RSVP is only available for invitations.");
  if (campaign.type !== "invitation" || campaign.rsvp_enabled !== 1) {
    throw new HttpError(400, "RSVP is not enabled for this invitation.");
  }

  // Clamp guest count
  const guests =
    status === "attending" ? Math.max(0, Math.min(20, Math.floor(guestCount ?? 1))) : 0;
  const msg = (message ?? "").slice(0, 500);
  const ts = now();

  const result = await env.DB.prepare(
    "UPDATE recipients SET rsvp_status = ?, rsvp_guest_count = ?, rsvp_message = ?, rsvped_at = ? WHERE id = ? AND rsvped_at IS NULL",
  )
    .bind(status, guests, msg || null, ts, recipient.id)
    .run();

  if (result.meta.changes === 0) {
    // Already submitted — return current state
    const current = await dbFirst<Recipient>(
      env.DB,
      "SELECT * FROM recipients WHERE id = ?",
      recipient.id,
    );
    return json({
      ok: true,
      alreadySubmitted: true,
      rsvpState: {
        submitted: true,
        status: current?.rsvp_status ?? null,
        guestCount: current?.rsvp_guest_count ?? null,
        message: current?.rsvp_message ?? null,
      },
    });
  }

  await dbRun(
    env.DB,
    "INSERT INTO activity_log (id, tenant_id, campaign_id, recipient_id, event_type, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    crypto.randomUUID(),
    campaign.tenant_id,
    campaign.id,
    recipient.id,
    "rsvp",
    JSON.stringify({ status, guestCount: guests }),
    ts,
  );

  return json({
    ok: true,
    rsvpState: { submitted: true, status, guestCount: guests, message: msg || null },
  });
}

// GET /api/image/:campaignId
export async function getImage(request: Request, env: Env, campaignId: string): Promise<Response> {
  const campaign = await dbFirst<Campaign>(
    env.DB,
    "SELECT * FROM campaigns WHERE id = ?",
    campaignId,
  );
  if (!campaign?.image_key) return new Response("Not found", { status: 404 });
  const obj = await env.IMAGES.get(campaign.image_key);
  if (!obj) return new Response("Not found", { status: 404 });
  return new Response(obj.body, {
    headers: {
      "Content-Type": obj.httpMetadata?.contentType ?? "application/octet-stream",
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}