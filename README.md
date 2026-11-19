# Wishcraft API (Cloudflare Worker)

One Worker hosts all customer tenants. Data in D1, images in R2.

## One-time setup (~5 min)

```bash
npm install
npx wrangler login

# 1. Create the database and bucket
npx wrangler d1 create wishcraft
# → copy the database_id into wrangler.toml
npx wrangler r2 bucket create wishcraft-images

# 2. Apply schema
npm run db:init:remote

# 3. Set secrets (generate long random values first)
openssl rand -base64 48    # → JWT_SECRET
openssl rand -base64 48    # → MASTER_SECRET

npx wrangler secret put JWT_SECRET
npx wrangler secret put MASTER_SECRET

# 4. Deploy
npm run deploy