import { cleanItem, getUser, json } from "../../_lib.js";

export async function onRequestGet(ctx) {
  const user = await getUser(ctx);
  if (!user) return json({ error: "not_logged_in" }, 401);

  const url = new URL(ctx.request.url);
  const item = cleanItem(url.searchParams.get("item"));
  const targetUser = user.is_admin ? String(url.searchParams.get("user_id") || user.id) : user.id;

  const { results } = await ctx.env.DB.prepare(
    "SELECT id, user_id, item, body, from_admin, created_at FROM messages WHERE user_id = ? AND item = ? ORDER BY id ASC LIMIT 200"
  ).bind(targetUser, item).all();

  return json({ messages: results, user });
}

export async function onRequestPost(ctx) {
  const user = await getUser(ctx);
  if (!user) return json({ error: "not_logged_in" }, 401);

  let data;

  try {
    data = await ctx.request.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }

  const item = cleanItem(data.item);
  const body = String(data.body || "").trim().slice(0, 800);
  const targetUser = user.is_admin ? String(data.user_id || "") : user.id;

  if (!body) return json({ error: "empty_message" }, 400);
  if (user.is_admin && !targetUser) return json({ error: "missing_user_id" }, 400);

  await ctx.env.DB.prepare(
    "INSERT INTO messages (user_id, item, body, from_admin, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(targetUser, item, body, user.is_admin ? 1 : 0, new Date().toISOString()).run();

  return json({ ok: true });
}
