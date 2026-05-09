export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function getCookie(req, name) {
  const raw = req.headers.get("cookie") || "";
  const parts = raw.split(";").map(v => v.trim());
  for (const part of parts) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    if (part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return "";
}

export function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export function b64uEncode(str) {
  return btoa(str).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function b64uDecode(str) {
  const pad = "=".repeat((4 - str.length % 4) % 4);
  return atob((str + pad).replaceAll("-", "+").replaceAll("_", "/"));
}

export function randomToken(size = 32) {
  const arr = new Uint8Array(size);
  crypto.getRandomValues(arr);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function safeNext(value) {
  if (!value || typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

export function cleanItem(value) {
  const item = String(value || "key").toLowerCase();
  if (item === "key") return "key";
  if (item === "script") return "script";
  if (item === "support") return "support";
  return "key";
}

export function itemTitle(item) {
  if (item === "key") return "Key";
  if (item === "script") return "Luau Script";
  if (item === "support") return "Support";
  return "Key";
}

export async function getUser(ctx) {
  const token = getCookie(ctx.request, "session");
  if (!token) return null;

  const row = await ctx.env.DB.prepare(
    "SELECT users.id, users.username, users.avatar FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?"
  ).bind(token).first();

  if (!row) return null;

  const adminId = ctx.env.ADMIN_DISCORD_ID || "1474054511130841234";

  return {
    id: row.id,
    username: row.username,
    avatar: row.avatar,
    is_admin: row.id === adminId
  };
}
