import { Env, HttpError, json, preflight } from "./lib";
import { postExperience, postMarkOpened, postMarkScratched, postRsvp, getImage, getThemeImage, getGiftImage, getSceneImage, } from "./public";
import {
  postLogin,
  getMe,
  listCampaigns,
  createCampaign,
  getCampaign,
  updateCampaign,
  deleteCampaign,
  publishCampaign,
  unpublishCampaign,
  uploadCampaignImage,
  uploadThemeImage,
  listRecipients,
  addRecipients,
  updateRecipient,
  deleteRecipient,
  regenerateRecipientToken,
  getStats,
  uploadGiftImage,
  uploadSceneImage,
} from "./admin";
import {
  postProvision,
  listTenants,
  deleteTenant,
  resetTenantPassword,
  updateTenantPlan
} from "./master";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") return preflight();

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const method = request.method;

    try {
      // Health
      if (url.pathname === "/api/health") {
        return json({
          ok: true,
          configured: {
            db: !!env.DB,
            images: !!env.IMAGES,
            jwtSecret: !!env.JWT_SECRET,
            masterSecret: !!env.MASTER_SECRET,
          },
        });
      }

      // Public
      if (parts[0] === "api" && parts[1] === "public") {
        const action = parts[2];
        if (action === "experience" && method === "POST") return await postExperience(request, env);
        if (action === "mark-opened" && method === "POST") return await postMarkOpened(request, env);
        if (action === "mark-scratched" && method === "POST")
          return await postMarkScratched(request, env);
        if (action === "rsvp" && method === "POST") return await postRsvp(request, env);
      }

      // Image
      if (parts[0] === "api" && parts[1] === "image" && parts[2] && method === "GET") {
        return await getImage(request, env, parts[2]);
      }

      if (parts[0] === "api" && parts[1] === "theme-image" && parts[2] && method === "GET") {
        return await getThemeImage(request, env, parts[2]);
      }

      if (parts[0] === "api" && parts[1] === "gift-image" && parts[2] && method === "GET") {
        return await getGiftImage(request, env, parts[2]);
      }
      if (parts[0] === "api" && parts[1] === "scene-image" && parts[2] && method === "GET") {
        return await getSceneImage(request, env, parts[2]);
      }

      // Admin
      if (parts[0] === "api" && parts[1] === "admin") {
        const action = parts[2];
        if (action === "login" && method === "POST") return await postLogin(request, env);
        if (action === "me" && method === "GET") return await getMe(request, env);
        if (action === "stats" && method === "GET") return await getStats(request, env);
        if (action === "campaigns") {
          if (parts.length === 3) {
            if (method === "GET") return await listCampaigns(request, env);
            if (method === "POST") return await createCampaign(request, env);
          }
          if (parts[3]) {
            const campaignId = parts[3];
            const sub = parts[4];
            if (!sub) {
              if (method === "GET") return await getCampaign(request, env, campaignId);
              if (method === "PATCH") return await updateCampaign(request, env, campaignId);
              if (method === "DELETE") return await deleteCampaign(request, env, campaignId);
            }
            if (sub === "publish" && method === "POST") return await publishCampaign(request, env, campaignId);
            if (sub === "unpublish" && method === "POST") return await unpublishCampaign(request, env, campaignId);
            if (sub === "image" && method === "POST") return await uploadCampaignImage(request, env, campaignId);
            if (sub === "theme-image" && method === "POST")
              return await uploadThemeImage(request, env, campaignId);
            if (sub === "gift-image" && method === "POST")            // NEW
              return await uploadGiftImage(request, env, campaignId);  // NEW
            if (sub === "scene-image" && method === "POST")           // NEW
              return await uploadSceneImage(request, env, campaignId); // NEW
            if (sub === "recipients") {
              if (method === "GET") return await listRecipients(request, env, campaignId);
              if (method === "POST") return await addRecipients(request, env, campaignId);
            }
          }
        }
        if (action === "recipients" && parts[3]) {
          const recipientId = parts[3];
          const sub = parts[4];
          if (!sub && method === "PATCH") return await updateRecipient(request, env, recipientId);
          if (!sub && method === "DELETE") return await deleteRecipient(request, env, recipientId);
          if (sub === "regenerate" && method === "POST")
            return await regenerateRecipientToken(request, env, recipientId);
        }
      }

      // Master
      if (parts[0] === "api" && parts[1] === "master") {
        const action = parts[2];
        if (action === "provision" && method === "POST") return await postProvision(request, env);
        if (action === "tenants") {
          if (method === "GET") return await listTenants(request, env);
          if (parts[3]) {
            const slug = parts[3];
            const sub = parts[4];
            if (!sub && method === "DELETE") return await deleteTenant(request, env, slug);
            if (sub === "reset-password" && method === "POST") return await resetTenantPassword(request, env, slug);
            if (sub === "plan" && method === "POST") return await updateTenantPlan(request, env, slug);
          }
        }
      }

      return json({ error: "Not found" }, 404);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error("Unhandled:", e);
      return json({ error: "Server error" }, 500);
    }
  },
};