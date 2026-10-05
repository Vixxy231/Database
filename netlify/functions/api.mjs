import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const st = () => getStore("patungan");
const env = (k) => process.env[k] || "";
const admins = () => env("ADMIN_DISCORD_IDS").split(",").map((s) => s.trim()).filter(Boolean);
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const hmac = (b) => crypto.createHmac("sha256", env("SESSION_SECRET")).update(b).digest("base64url");

function sign(p) { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + hmac(b); }
function verify(t) {
  if (!t || !env("SESSION_SECRET")) return null;
  const [b, sig] = t.split(".");
  if (!b || !sig) return null;
  const x = Buffer.from(hmac(b)), y = Buffer.from(sig);
  if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
  try { const p = JSON.parse(Buffer.from(b, "base64url")); return p.exp > Date.now() ? p : null; } catch { return null; }
}
const getCookie = (req, n) => {
  for (const c of (req.headers.get("cookie") || "").split(/;\s*/)) { const i = c.indexOf("="); if (c.slice(0, i) === n) return c.slice(i + 1); }
  return null;
};
const setCookie = (n, v, age) => `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const str = (v, n) => String(v ?? "").slice(0, n);
const rid = () => crypto.randomBytes(6).toString("hex");

const DEFAULT = {
  org: "DKMR AREA", wa: "", qris: "/qris.jpg", expenses: [],
  campaigns: [{ id: "c1", title: "Kas & Patungan DKMR AREA", desc: "Dana bersama untuk kegiatan dan kebutuhan komunitas DKMR AREA.", target: 5000000, deadline: "", active: true }],
};
const getConfig = async () => (await st().get("config", { type: "json" })) || DEFAULT;
async function allDonations() {
  const { blobs } = await st().list({ prefix: "don/" });
  const rows = await Promise.all(blobs.map((b) => st().get(b.key, { type: "json" })));
  return rows.filter(Boolean);
}

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "") || "/";
  const method = req.method;
  const sess = verify(getCookie(req, "session"));
  const isAdmin = !!sess && admins().includes(sess.id);

  // ---- Discord OAuth (scope identify saja; tidak butuh server Discord) ----
  if (path === "/auth/login") {
    if (!env("DISCORD_CLIENT_ID")) return J({ error: "DISCORD_CLIENT_ID belum diatur" }, 500);
    const state = crypto.randomBytes(16).toString("hex");
    const q = new URLSearchParams({ client_id: env("DISCORD_CLIENT_ID"), response_type: "code", scope: "identify", state, redirect_uri: url.origin + "/api/auth/callback" });
    const h = new Headers({ location: "https://discord.com/oauth2/authorize?" + q });
    h.append("set-cookie", setCookie("oauth_state", state, 600));
    return new Response(null, { status: 302, headers: h });
  }
  if (path === "/auth/callback") {
    const code = url.searchParams.get("code"), state = url.searchParams.get("state");
    if (!code || !state || state !== getCookie(req, "oauth_state")) return new Response("State tidak valid. Coba login ulang.", { status: 400 });
    const tr = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: env("DISCORD_CLIENT_ID"), client_secret: env("DISCORD_CLIENT_SECRET"), grant_type: "authorization_code", code, redirect_uri: url.origin + "/api/auth/callback" }),
    });
    if (!tr.ok) return new Response("Gagal login Discord.", { status: 400 });
    const { access_token } = await tr.json();
    const ur = await fetch("https://discord.com/api/users/@me", { headers: { authorization: "Bearer " + access_token } });
    if (!ur.ok) return new Response("Gagal membaca akun Discord.", { status: 400 });
    const u = await ur.json();
    const token = sign({ id: u.id, name: u.global_name || u.username, exp: Date.now() + 7 * 864e5 });
    const h = new Headers({ location: "/" });
    h.append("set-cookie", setCookie("session", token, 7 * 86400));
    h.append("set-cookie", setCookie("oauth_state", "", 0));
    return new Response(null, { status: 302, headers: h });
  }
  if (path === "/auth/logout") {
    return new Response(null, { status: 302, headers: { location: "/", "set-cookie": setCookie("session", "", 0) } });
  }
  if (path === "/me") return J({ user: sess ? { id: sess.id, name: sess.name } : null, isAdmin });

  // ---- Data publik ----
  if (path === "/data" && method === "GET") {
    const config = await getConfig();
    const donations = (await allDonations()).map((d) => ({
      id: d.id, cid: d.cid, amt: d.amt, total: d.total, msg: d.msg, anon: d.anon, date: d.date, status: d.status,
      name: d.anon && !isAdmin ? "Hamba Allah" : d.name, ...(isAdmin ? { dc: d.dc } : {}),
    }));
    return J({ config, donations });
  }

  // ---- Tulis: cek Origin (anti-CSRF) ----
  if (method !== "GET") {
    const o = req.headers.get("origin");
    if (!o || o !== url.origin) return J({ error: "Origin tidak valid" }, 403);
  }
  const body = method === "GET" || method === "DELETE" ? {} : await req.json().catch(() => ({}));

  // Donatur mencatat patungan (status: menunggu verifikasi)
  if (path === "/donations" && method === "POST") {
    const cfg = await getConfig();
    const amt = parseInt(body.amt), uniq = parseInt(body.uniq) || 0, name = str(body.name, 60).trim();
    if (!cfg.campaigns.some((c) => c.id === body.cid && c.active)) return J({ error: "Kampanye tidak valid" }, 400);
    if (!(amt >= 1000 && amt <= 1e8) || uniq < 0 || uniq > 99 || !name) return J({ error: "Data tidak valid" }, 400);
    const pending = (await allDonations()).filter((d) => d.status === "pending").length;
    if (pending >= 500) return J({ error: "Antrian penuh, hubungi admin" }, 429);
    const d = { id: rid(), cid: body.cid, name, amt, total: amt + uniq, msg: str(body.msg, 200), anon: !!body.anon, date: new Date().toISOString().slice(0, 10), status: "pending", dc: sess ? sess.name : "", did: sess ? sess.id : "" };
    await st().setJSON("don/" + d.id, d);
    return J({ ok: true });
  }

  // ---- Admin ----
  if (!path.startsWith("/admin")) return J({ error: "Not found" }, 404);
  if (!isAdmin) return J({ error: "Khusus admin" }, 403);

  if (path === "/admin/state" && method === "PUT") {
    const qris = str(body.qris, 2_000_000);
    const cfg = {
      org: str(body.org, 80) || "DKMR AREA",
      wa: str(body.wa, 20).replace(/\D/g, ""),
      qris: qris.startsWith("data:image/") || qris.startsWith("/") ? qris : "/qris.jpg",
      campaigns: (Array.isArray(body.campaigns) ? body.campaigns : []).slice(0, 50).map((c) => ({ id: str(c.id, 20), title: str(c.title, 120), desc: str(c.desc, 500), target: Math.max(0, parseInt(c.target) || 0), deadline: str(c.deadline, 10), active: !!c.active })),
      expenses: (Array.isArray(body.expenses) ? body.expenses : []).slice(0, 2000).map((e) => ({ id: str(e.id, 20), cid: str(e.cid, 20), desc: str(e.desc, 200), amt: Math.max(0, parseInt(e.amt) || 0), date: str(e.date, 10) })),
    };
    await st().setJSON("config", cfg);
    // hapus donasi milik kampanye yang sudah dihapus
    const ids = new Set(cfg.campaigns.map((c) => c.id));
    for (const d of await allDonations()) if (!ids.has(d.cid)) await st().delete("don/" + d.id);
    return J({ ok: true });
  }
  if (path === "/admin/donations" && method === "POST") {
    const amt = parseInt(body.amt), name = str(body.name, 60).trim();
    if (!(amt > 0) || !name) return J({ error: "Data tidak valid" }, 400);
    const d = { id: rid(), cid: str(body.cid, 20), name, amt, total: amt, msg: str(body.msg, 200), anon: !!body.anon, date: new Date().toISOString().slice(0, 10), status: "ok", dc: "", did: "" };
    await st().setJSON("don/" + d.id, d);
    return J({ ok: true });
  }
  let m = path.match(/^\/admin\/donations\/([a-f0-9]+)\/verify$/);
  if (m && method === "POST") {
    const d = await st().get("don/" + m[1], { type: "json" });
    if (!d) return J({ error: "Tidak ditemukan" }, 404);
    d.status = "ok";
    await st().setJSON("don/" + d.id, d);
    return J({ ok: true });
  }
  m = path.match(/^\/admin\/donations\/([a-f0-9]+)$/);
  if (m && method === "DELETE") { await st().delete("don/" + m[1]); return J({ ok: true }); }
  return J({ error: "Not found" }, 404);
};

export const config = { path: "/api/*" };
