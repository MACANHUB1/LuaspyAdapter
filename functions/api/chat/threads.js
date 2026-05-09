import { getUser, json } from "../../_lib.js";

export async function onRequestGet(ctx) {
  const user = await getUser(ctx);
  if (!user) return json({ error: "not_logged_in" }, 401);
  if (!user.is_admin) return json({ error: "admin_only" }, 403);

  const { results } = await ctx.env.DB.prepare(
    "SELECT m.user_id, m.item, u.username, u.avatar, MAX(m.created_at) AS updated_at, (SELECT body FROM messages x WHERE x.user_id = m.user_id AND x.item = m.item ORDER BY x.id DESC LIMIT 1) AS last_body FROM messages m LEFT JOIN users u ON u.id = m.user_id GROUP BY m.user_id, m.item ORDER BY MAX(m.id) DESC LIMIT 100"
  ).all();

  return json({ threads: results });
}
