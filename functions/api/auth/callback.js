import { b64uDecode, clearCookie, getCookie, json, randomToken, setCookie, safeNext } from "../../_lib.js";

export async function onRequestGet(ctx) {
  const url = new URL(ctx.request.url);
  const code = url.searchParams.get("code");
  const stateRaw = url.searchParams.get("state");
  const savedState = getCookie(ctx.request, "oauth_state");

  if (!code || !stateRaw || !savedState) return json({ error: "bad_oauth_state" }, 401);

  let state;

  try {
    state = JSON.parse(b64uDecode(stateRaw));
  } catch {
    return json({ error: "bad_oauth_state" }, 401);
  }

  if (!state.r || state.r !== savedState) return json({ error: "bad_oauth_state" }, 401);

  const redirectUri = ctx.env.DISCORD_REDIRECT_URI || `${url.origin}/api/auth/callback`;

  const form = new URLSearchParams();
  form.set("client_id", ctx.env.DISCORD_CLIENT_ID);
  form.set("client_secret", ctx.env.DISCORD_CLIENT_SECRET);
  form.set("grant_type", "authorization_code");
  form.set("code", code);
  form.set("redirect_uri", redirectUri);

  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form
  });

  if (!tokenRes.ok) return json({ error: "discord_token_failed" }, 401);

  const tokenData = await tokenRes.json();

  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: { authorization: `Bearer ${tokenData.access_token}` }
  });

  if (!userRes.ok) return json({ error: "discord_user_failed" }, 401);

  const user = await userRes.json();
  const now = new Date().toISOString();

  await ctx.env.DB.prepare(
    "INSERT INTO users (id, username, avatar, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, avatar = excluded.avatar, updated_at = excluded.updated_at"
  ).bind(user.id, user.username, user.avatar || "", now).run();

  const session = randomToken(32);

  await ctx.env.DB.prepare(
    "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)"
  ).bind(session, user.id, now).run();

  const headers = new Headers();
  headers.set("location", safeNext(state.n));
  headers.append("set-cookie", clearCookie("oauth_state"));
  headers.append("set-cookie", setCookie("session", session, 2592000));

  return new Response(null, { status: 302, headers });
}
