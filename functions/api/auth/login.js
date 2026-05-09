import { b64uEncode, randomToken, safeNext, setCookie } from "../../_lib.js";

export async function onRequestGet(ctx) {
  const url = new URL(ctx.request.url);
  const next = safeNext(url.searchParams.get("next"));
  const redirectUri = ctx.env.DISCORD_REDIRECT_URI || `${url.origin}/api/auth/callback`;
  const stateToken = randomToken(16);
  const state = b64uEncode(JSON.stringify({ r: stateToken, n: next }));

  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.searchParams.set("client_id", ctx.env.DISCORD_CLIENT_ID);
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
