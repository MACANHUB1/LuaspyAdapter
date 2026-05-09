import { getUser, json } from "../../_lib.js";

export async function onRequestGet(ctx) {
  const user = await getUser(ctx);
  if (!user) return json({ user: null }, 401);
  return json({ user });
}
