function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function getCookie(req, name) {
  const raw = req.headers.get("cookie") || "";
  const parts = raw.split(";").map(v => v.trim());

  for (const part of parts) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    if (part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }

  return "";
}

function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function b64uEncode(str) {
  return btoa(str).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64uDecode(str) {
  const pad = "=".repeat((4 - str.length % 4) % 4);
  return atob((str + pad).replaceAll("-", "+").replaceAll("_", "/"));
}

function randomToken(size = 32) {
  const arr = new Uint8Array(size);
  crypto.getRandomValues(arr);
  let s = "";

  for (const b of arr) {
    s += String.fromCharCode(b);
  }

  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function safeNext(value) {
  if (!value || typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function cleanUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanItem(value) {
  const item = String(value || "key").toLowerCase();

  if (item === "key") return "key";
  if (item === "script") return "script";
  if (item === "ban") return "ban";

  return "key";
}

function cleanPlan(value) {
  const plan = String(value || "").toLowerCase();

  if (plan === "30d") return "30d";
  if (plan === "lifetime") return "lifetime";

  return "";
}

function makeThread(item, plan) {
  const clean = cleanItem(item);
  const p = cleanPlan(plan);

  if (clean === "key" && p) return `${clean}:${p}`;

  return clean;
}

function parseThread(thread) {
  const value = String(thread || "key").toLowerCase();

  if (value === "key:30d") return { item: "key", plan: "30d", title: "Key · 30 Days" };
  if (value === "key:lifetime") return { item: "key", plan: "lifetime", title: "Key · Lifetime" };
  if (value === "script") return { item: "script", plan: "", title: "Luau Script" };
  if (value === "ban") return { item: "ban", plan: "", title: "War Tycoon Ban" };

  return { item: "key", plan: "", title: "Key" };
}

async function getUser(req, env) {
  const token = getCookie(req, "session");
  if (!token) return null;

  const row = await env.DB.prepare(
    "SELECT users.username, users.avatar FROM sessions JOIN users ON users.username = sessions.username WHERE sessions.token = ?"
  ).bind(token).first();

  if (!row) return null;

  const username = cleanUsername(row.username);
  const admin = cleanUsername(env.ADMIN_USERNAME || "lua.spy");

  return {
    username,
    avatar: row.avatar || "",
    is_admin: username === admin
  };
}

async function authLogin(req, env) {
  const url = new URL(req.url);
  const next = safeNext(url.searchParams.get("next"));
  const redirectUri = env.DISCORD_REDIRECT_URI || `${url.origin}/api/auth/callback`;
  const stateToken = randomToken(16);
  const state = b64uEncode(JSON.stringify({ r: stateToken, n: next }));

  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
  auth.searchParams.set("redirect_uri", redirectUri);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "identify");
  auth.searchParams.set("state", state);

  return new Response(null, {
    status: 302,
    headers: {
      location: auth.toString(),
      "set-cookie": setCookie("oauth_state", stateToken, 600)
    }
  });
}

async function authCallback(req, env) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const stateRaw = url.searchParams.get("state");
  const savedState = getCookie(req, "oauth_state");

  if (!code || !stateRaw || !savedState) return json({ error: "bad_oauth_state" }, 401);

  let state;

  try {
    state = JSON.parse(b64uDecode(stateRaw));
  } catch {
    return json({ error: "bad_oauth_state" }, 401);
  }

  if (!state.r || state.r !== savedState) return json({ error: "bad_oauth_state" }, 401);

  const redirectUri = env.DISCORD_REDIRECT_URI || `${url.origin}/api/auth/callback`;

  const form = new URLSearchParams();
  form.set("client_id", env.DISCORD_CLIENT_ID);
  form.set("client_secret", env.DISCORD_CLIENT_SECRET);
  form.set("grant_type", "authorization_code");
  form.set("code", code);
  form.set("redirect_uri", redirectUri);

  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: form
  });

  if (!tokenRes.ok) return json({ error: "discord_token_failed" }, 401);

  const tokenData = await tokenRes.json();

  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: {
      authorization: `Bearer ${tokenData.access_token}`
    }
  });

  if (!userRes.ok) return json({ error: "discord_user_failed" }, 401);

  const user = await userRes.json();
  const username = cleanUsername(user.username);

  if (!username) return json({ error: "discord_username_missing" }, 401);

  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO users (username, avatar, updated_at) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET avatar = excluded.avatar, updated_at = excluded.updated_at"
  ).bind(username, user.avatar || "", now).run();

  const session = randomToken(32);

  await env.DB.prepare(
    "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)"
  ).bind(session, username, now).run();

  const headers = new Headers();
  headers.set("location", safeNext(state.n));
  headers.append("set-cookie", clearCookie("oauth_state"));
  headers.append("set-cookie", setCookie("session", session, 2592000));

  return new Response(null, { status: 302, headers });
}

async function authMe(req, env) {
  const user = await getUser(req, env);
  return json({ user });
}

async function authLogout(req, env) {
  const token = getCookie(req, "session");

  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "set-cookie": clearCookie("session")
    }
  });
}

async function chatMessagesGet(req, env) {
  const user = await getUser(req, env);
  if (!user) return json({ error: "not_logged_in" }, 401);

  const url = new URL(req.url);

  const thread = user.is_admin && url.searchParams.get("thread")
    ? String(url.searchParams.get("thread"))
    : makeThread(url.searchParams.get("item"), url.searchParams.get("plan"));

  const targetUsername = user.is_admin
    ? cleanUsername(url.searchParams.get("username"))
    : user.username;

  if (user.is_admin && !targetUsername) return json({ error: "missing_username" }, 400);

  const { results } = await env.DB.prepare(
    "SELECT id, username, thread, body, from_admin, created_at FROM messages WHERE username = ? AND thread = ? ORDER BY id ASC LIMIT 300"
  ).bind(targetUsername, thread).all();

  return json({
    messages: results,
    thread,
    meta: parseThread(thread),
    user
  });
}

async function chatMessagesPost(req, env) {
  const user = await getUser(req, env);
  if (!user) return json({ error: "not_logged_in" }, 401);

  let data;

  try {
    data = await req.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }

  const thread = user.is_admin && data.thread
    ? String(data.thread)
    : makeThread(data.item, data.plan);

  const body = String(data.body || "").trim().slice(0, 800);
  const targetUsername = user.is_admin
    ? cleanUsername(data.username)
    : user.username;

  if (!body) return json({ error: "empty_message" }, 400);
  if (user.is_admin && !targetUsername) return json({ error: "missing_username" }, 400);

  await env.DB.prepare(
    "INSERT INTO messages (username, thread, body, from_admin, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(targetUsername, thread, body, user.is_admin ? 1 : 0, new Date().toISOString()).run();

  return json({ ok: true, thread, meta: parseThread(thread) });
}

async function chatThreads(req, env) {
  const user = await getUser(req, env);
  if (!user) return json({ error: "not_logged_in" }, 401);
  if (!user.is_admin) return json({ error: "admin_only" }, 403);

  const { results } = await env.DB.prepare(
    "SELECT m.username, m.thread, u.avatar, MAX(m.created_at) AS updated_at, (SELECT body FROM messages x WHERE x.username = m.username AND x.thread = m.thread ORDER BY x.id DESC LIMIT 1) AS last_body FROM messages m LEFT JOIN users u ON u.username = m.username GROUP BY m.username, m.thread ORDER BY MAX(m.id) DESC LIMIT 100"
  ).all();

  const threads = results.map(t => ({
    ...t,
    meta: parseThread(t.thread)
  }));

  return json({ threads });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    try {
      if (path === "/api/auth/login" && req.method === "GET") return authLogin(req, env);
      if (path === "/api/auth/callback" && req.method === "GET") return authCallback(req, env);
      if (path === "/api/auth/me" && req.method === "GET") return authMe(req, env);
      if (path === "/api/auth/logout" && req.method === "POST") return authLogout(req, env);

      if (path === "/api/chat/messages" && req.method === "GET") return chatMessagesGet(req, env);
      if (path === "/api/chat/messages" && req.method === "POST") return chatMessagesPost(req, env);
      if (path === "/api/chat/threads" && req.method === "GET") return chatThreads(req, env);

      if (path.startsWith("/api/")) return json({ error: "not_found" }, 404);

      return env.ASSETS.fetch(req);
    } catch (err) {
      return json({ error: "server_error", message: String(err && err.message ? err.message : err) }, 500);
    }
  }
};
