-- Run once: wrangler d1 execute wishcraft --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  customer_name TEXT NOT NULL,
  admin_username TEXT NOT NULL,
  admin_password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('wish', 'invitation')),
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
  sender_name TEXT NOT NULL,
  reveal_message TEXT NOT NULL,
  image_key TEXT,
  image_content_type TEXT,
  event_title TEXT,
  event_description TEXT,
  event_date TEXT,          -- ISO 8601 date: YYYY-MM-DD
  event_time TEXT,          -- 24h HH:MM
  event_location TEXT,
  rsvp_enabled INTEGER NOT NULL DEFAULT 0,
  shared_token TEXT UNIQUE, -- populated on publish for wish campaigns
  preview_token TEXT UNIQUE NOT NULL,
  open_count INTEGER NOT NULL DEFAULT 0,
  scratch_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_shared_token ON campaigns(shared_token);
CREATE INDEX IF NOT EXISTS idx_campaigns_preview_token ON campaigns(preview_token);

CREATE TABLE IF NOT EXISTS recipients (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  opened_at INTEGER,
  scratched_at INTEGER,
  rsvp_status TEXT CHECK (rsvp_status IN ('attending', 'not_attending')),
  rsvp_guest_count INTEGER,
  rsvp_message TEXT,
  rsvped_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_recipients_campaign ON recipients(campaign_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recipients_token ON recipients(token);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  campaign_id TEXT NOT NULL,
  recipient_id TEXT,
  event_type TEXT NOT NULL CHECK (event_type IN ('opened', 'scratched', 'rsvp')),
  metadata TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id, created_at DESC);