import { clearCookie, getCookie, json } from "../../_lib.js";

export async function onRequestPost(ctx) {
  const token = getCookie(ctx.request, "session");

  if (token) {
    await ctx.env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "set-cookie": clearCookie("session")
    }
  });
}
