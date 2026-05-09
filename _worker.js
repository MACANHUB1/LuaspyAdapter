const ADMIN_USERNAME = "lua.spy";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  });
}

function redirect(to, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: {
      location: to,
      ...headers
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
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax`;
}

function setHttpCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function b64uEncode(str) {
  return btoa(str).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64uDecode(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
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

function cleanUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function safeNext(value) {
  const v = String(value || "/");

  if (!v.startsWith("/") || v.startsWith("//")) return "/";

  return v;
}

function cleanItem(value) {
  const v = String(value || "key").toLowerCase();

  if (v === "key") return "key";
  if (v === "script") return "script";
  if (v === "ban") return "ban";

  return "key";
}

function cleanPlan(value) {
  const v = String(value || "").toLowerCase();

  if (v === "30d") return "30d";
  if (v === "lifetime") return "lifetime";

  return "";
}

function makeThread(item, plan) {
  const clean = cleanItem(item);
  const p = cleanPlan(plan);

  if (clean === "key" && p) return `key:${p}`;

  return clean;
}

function parseThread(thread) {
  const v = String(thread || "key").toLowerCase();

  if (v === "anonymous") return { item: "anonymous", plan: "", title: "Anonymous Message" };
  if (v === "key:30d") return { item: "key", plan: "30d", title: "Key · 30 Days" };
  if (v === "key:lifetime") return { item: "key", plan: "lifetime", title: "Key · Lifetime" };
  if (v === "script") return { item: "script", plan: "", title: "Luau Script" };
  if (v === "ban") return { item: "ban", plan: "", title: "War Tycoon Ban" };

  return { item: "key", plan: "", title: "Key" };
}

async function setupDb(env) {
  if (!env.DB) throw new Error("D1 binding DB is missing");

  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, avatar TEXT, updated_at TEXT NOT NULL)"
  ).run();

  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at TEXT NOT NULL)"
  ).run();

  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, thread TEXT NOT NULL, body TEXT NOT NULL, from_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)"
  ).run();

  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)"
  ).run();

  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(username, thread, id)"
  ).run();
}

function getAnon(req) {
  const raw = getCookie(req, "anon");
  if (raw && raw.startsWith("anon_") && raw.length <= 80) return raw;
  return `anon_${randomToken(18)}`;
}

async function getUser(req, env) {
  await setupDb(env);

  const token = getCookie(req, "session");
  if (!token) return null;

  const row = await env.DB.prepare(
    "SELECT users.username, users.avatar FROM sessions JOIN users ON users.username = sessions.username WHERE sessions.token = ?"
  ).bind(token).first();

  if (!row) return null;

  const username = cleanUsername(row.username);

  return {
    username,
    avatar: row.avatar || "",
    is_admin: username === cleanUsername(env.ADMIN_USERNAME || ADMIN_USERNAME)
  };
}

async function authLogin(req, env) {
  if (!env.DISCORD_CLIENT_ID) return json({ error: "missing_DISCORD_CLIENT_ID" }, 500);

  const url = new URL(req.url);
  const next = safeNext(url.searchParams.get("next"));
  const redirectUri = env.DISCORD_REDIRECT_URI || `${url.origin}/api/auth/callback`;
  const stateToken = randomToken(16);
  const state = b64uEncode(JSON.stringify({ token: stateToken, next }));

  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
  auth.searchParams.set("redirect_uri", redirectUri);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "identify");
  auth.searchParams.set("state", state);

  return redirect(auth.toString(), {
    "set-cookie": setHttpCookie("oauth_state", stateToken, 600)
  });
}

async function authCallback(req, env) {
  await setupDb(env);

  if (!env.DISCORD_CLIENT_ID) return json({ error: "missing_DISCORD_CLIENT_ID" }, 500);
  if (!env.DISCORD_CLIENT_SECRET) return json({ error: "missing_DISCORD_CLIENT_SECRET" }, 500);

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

  if (!state.token || state.token !== savedState) {
    return json({ error: "bad_oauth_state" }, 401);
  }

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

  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    return json({ error: "discord_token_failed", detail: body.slice(0, 300) }, 401);
  }

  const tokenData = await tokenRes.json();

  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: {
      authorization: `Bearer ${tokenData.access_token}`
    }
  });

  if (!userRes.ok) {
    const body = await userRes.text();
    return json({ error: "discord_user_failed", detail: body.slice(0, 300) }, 401);
  }

  const discordUser = await userRes.json();
  const username = cleanUsername(discordUser.username);

  if (!username) return json({ error: "discord_username_missing" }, 401);

  const now = new Date().toISOString();
  const session = randomToken(32);

  await env.DB.prepare(
    "INSERT INTO users (username, avatar, updated_at) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET avatar = excluded.avatar, updated_at = excluded.updated_at"
  ).bind(username, discordUser.avatar || "", now).run();

  await env.DB.prepare(
    "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)"
  ).bind(session, username, now).run();

  const headers = new Headers();
  headers.set("location", safeNext(state.next));
  headers.append("set-cookie", clearCookie("oauth_state"));
  headers.append("set-cookie", setHttpCookie("session", session, 2592000));

  return new Response(null, {
    status: 302,
    headers
  });
}

async function authMe(req, env) {
  const user = await getUser(req, env);
  return json({ user });
}

async function authLogout(req, env) {
  await setupDb(env);

  const token = getCookie(req, "session");

  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }

  return json({ ok: true }, 200, {
    "set-cookie": clearCookie("session")
  });
}

async function anonMessagesGet(req, env) {
  await setupDb(env);

  const anon = getAnon(req);

  const { results } = await env.DB.prepare(
    "SELECT id, username, thread, body, from_admin, created_at FROM messages WHERE username = ? AND thread = ? ORDER BY id ASC LIMIT 300"
  ).bind(anon, "anonymous").all();

  return json({
    anon,
    thread: "anonymous",
    meta: parseThread("anonymous"),
    messages: results || []
  }, 200, {
    "set-cookie": setCookie("anon", anon, 2592000)
  });
}

async function anonMessagesPost(req, env) {
  await setupDb(env);

  let data;

  try {
    data = await req.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }

  const body = String(data.body || "").trim().slice(0, 800);

  if (!body) return json({ error: "empty_message" }, 400);

  const anon = getAnon(req);

  await env.DB.prepare(
    "INSERT INTO messages (username, thread, body, from_admin, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(anon, "anonymous", body, 0, new Date().toISOString()).run();

  return json({
    ok: true,
    anon,
    thread: "anonymous",
    meta: parseThread("anonymous")
  }, 200, {
    "set-cookie": setCookie("anon", anon, 2592000)
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

  if (!targetUsername) return json({ error: "missing_username" }, 400);

  const { results } = await env.DB.prepare(
    "SELECT id, username, thread, body, from_admin, created_at FROM messages WHERE username = ? AND thread = ? ORDER BY id ASC LIMIT 300"
  ).bind(targetUsername, thread).all();

  return json({
    user,
    thread,
    meta: parseThread(thread),
    messages: results || []
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

  const targetUsername = user.is_admin
    ? cleanUsername(data.username)
    : user.username;

  const body = String(data.body || "").trim().slice(0, 800);

  if (!targetUsername) return json({ error: "missing_username" }, 400);
  if (!body) return json({ error: "empty_message" }, 400);

  await env.DB.prepare(
    "INSERT INTO messages (username, thread, body, from_admin, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(targetUsername, thread, body, user.is_admin ? 1 : 0, new Date().toISOString()).run();

  return json({
    ok: true,
    thread,
    meta: parseThread(thread)
  });
}

async function chatThreads(req, env) {
  const user = await getUser(req, env);

  if (!user) return json({ error: "not_logged_in" }, 401);
  if (!user.is_admin) return json({ error: "admin_only" }, 403);

  const { results } = await env.DB.prepare(
    "SELECT m.username, m.thread, u.avatar, MAX(m.created_at) AS updated_at, (SELECT body FROM messages x WHERE x.username = m.username AND x.thread = m.thread ORDER BY x.id DESC LIMIT 1) AS last_body FROM messages m LEFT JOIN users u ON u.username = m.username GROUP BY m.username, m.thread ORDER BY MAX(m.id) DESC LIMIT 100"
  ).all();

  return json({
    threads: (results || []).map(t => ({
      ...t,
      display: t.thread === "anonymous" ? "Anonymous" : t.username,
      meta: parseThread(t.thread)
    }))
  });
}

async function handleApi(req, env, path) {
  if (path === "/api/auth/login" && req.method === "GET") return authLogin(req, env);
  if (path === "/api/auth/callback" && req.method === "GET") return authCallback(req, env);
  if (path === "/api/auth/me" && req.method === "GET") return authMe(req, env);
  if (path === "/api/auth/logout" && req.method === "POST") return authLogout(req, env);

  if (path === "/api/anon/messages" && req.method === "GET") return anonMessagesGet(req, env);
  if (path === "/api/anon/messages" && req.method === "POST") return anonMessagesPost(req, env);

  if (path === "/api/chat/messages" && req.method === "GET") return chatMessagesGet(req, env);
  if (path === "/api/chat/messages" && req.method === "POST") return chatMessagesPost(req, env);
  if (path === "/api/chat/threads" && req.method === "GET") return chatThreads(req, env);

  if (path === "/api/debug" && req.method === "GET") {
    return json({
      ok: true,
      hasDB: !!env.DB,
      hasASSETS: !!env.ASSETS,
      hasClientId: !!env.DISCORD_CLIENT_ID,
      hasClientSecret: !!env.DISCORD_CLIENT_SECRET,
      redirectUri: env.DISCORD_REDIRECT_URI || null,
      adminUsername: env.ADMIN_USERNAME || ADMIN_USERNAME
    });
  }

  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(req, env, url.pathname);
      }

      if (env.ASSETS) {
        return await env.ASSETS.fetch(req);
      }

      return new Response("ASSETS binding missing", { status: 500 });
    } catch (err) {
      return json({
        error: "server_error",
        message: String(err && err.message ? err.message : err)
      }, 500);
    }
  }
};
