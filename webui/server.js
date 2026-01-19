import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { Client } from "pg";
import Docker from "dockerode";
import { WebSocketServer } from "ws";
import pty from "node-pty";
import fs from "fs";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || "8090", 10);
const DATABASE_URL = process.env.DATABASE_URL;
const TRUST_PROXY_COUNT = (() => {
  const raw = process.env.TRUST_PROXY_COUNT || "0";
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
})();

if (!DATABASE_URL) {
  console.error("[icloudpd-webui] DATABASE_URL is required");
  process.exit(1);
}

const MASTER_KEY_B64 = process.env.MASTER_KEY;
if (!MASTER_KEY_B64) {
  console.error("[icloudpd-webui] MASTER_KEY is required (base64 for 32 bytes) to store iCloud passwords securely");
  process.exit(1);
}
let MASTER_KEY;
try {
  MASTER_KEY = Buffer.from(MASTER_KEY_B64, "base64");
  if (MASTER_KEY.length !== 32) throw new Error("bad_key_len");
} catch {
  console.error("[icloudpd-webui] MASTER_KEY must be base64 for exactly 32 bytes");
  process.exit(1);
}


const app = express();
app.set("trust proxy", TRUST_PROXY_COUNT);

const server = http.createServer(app);

// Security headers (keep compatible with local LAN deployments)
app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// Rate limiting: only for auth/setup endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  skipSuccessfulRequests: true,
});

app.use("/api/login", authLimiter);
app.use("/api/setup", authLimiter);
app.use("/api/admin/reset-password", authLimiter);

// No-cache for HTML to avoid stale login/app loops
function noStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir, {
  maxAge: 0,
  setHeaders(res, p) {
    if (p.endsWith(".html")) noStore(res);
  }
}));

// Database connection helper
async function withDb(fn) {
  const c = new Client({ connectionString: DATABASE_URL });
  await c.connect();
  try { return await fn(c); } finally { await c.end(); }
}

// Migrations + settings
async function initDb() {
  await withDb(async (c) => {
    await c.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS webui_users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS icloud_accounts (
        id SERIAL PRIMARY KEY,
        label TEXT NOT NULL,
        apple_id TEXT NOT NULL,
        apple_password_enc TEXT NOT NULL,
        authentication_type TEXT NOT NULL DEFAULT '2FA',
        container_user TEXT NOT NULL DEFAULT 'user',
        user_id INTEGER NOT NULL DEFAULT 1000,
        group_id INTEGER NOT NULL DEFAULT 1000,
        download_path TEXT NOT NULL,
        synchronisation_interval INTEGER NOT NULL DEFAULT 86400,
        skip_created_before TEXT,
        skip_created_after TEXT,
        folder_structure TEXT,
        directory_permissions TEXT,
        file_permissions TEXT,
        convert_heic_to_jpeg TEXT,
        delete_heic_jpegs TEXT,
        command_line_options TEXT,
        notification_days INTEGER,
        notification_type TEXT,
        prowl_api_key TEXT,
        pushbullet_api_key TEXT,
        telegram_token TEXT,
        telegram_chat_id TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS accounts (
        id SERIAL PRIMARY KEY,
        label TEXT NOT NULL,
        apple_id TEXT NOT NULL,
        authentication_type TEXT NOT NULL DEFAULT '2FA',
        container_user TEXT NOT NULL DEFAULT 'user',
        user_id INTEGER NOT NULL DEFAULT 1000,
        group_id INTEGER NOT NULL DEFAULT 1000,
        download_path TEXT NOT NULL,
        synchronisation_interval INTEGER NOT NULL DEFAULT 86400,
        folder_structure TEXT,
        directory_permissions TEXT,
        file_permissions TEXT,
        convert_heic_to_jpeg TEXT,
        delete_heic_jpegs TEXT,
        command_line_options TEXT,
        notification_days INTEGER,
        notification_type TEXT,
        prowl_api_key TEXT,
        pushbullet_api_key TEXT,
        telegram_token TEXT,
        telegram_chat_id TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // DB migrations (idempotent)
    await c.query("ALTER TABLE icloud_accounts ADD COLUMN IF NOT EXISTS skip_created_before TEXT");
    await c.query("ALTER TABLE icloud_accounts ADD COLUMN IF NOT EXISTS skip_created_after TEXT");

    const r = await c.query("SELECT value FROM app_settings WHERE key='jwt_secret'");
    if (r.rowCount === 0) {
      const secret = cryptoRandom(48);
      await c.query("INSERT INTO app_settings(key,value) VALUES('jwt_secret',$1)", [secret]);
    }

    // Admin password reset token (used by login page for break-glass password resets)
    // If ADMIN_RESET_TOKEN is set, it will be accepted as an override.
    const rr = await c.query("SELECT value FROM app_settings WHERE key='admin_reset_token'");
    if (rr.rowCount === 0) {
      const token = cryptoRandom(32);
      await c.query("INSERT INTO app_settings(key,value) VALUES('admin_reset_token',$1)", [token]);
      if (!process.env.ADMIN_RESET_TOKEN) {
        console.log(`[icloudpd-webui] Generated admin reset token (store it safely): ${token}`);
      }
    }
  });
}

function cryptoRandom(len) {
  // simple random string; sufficient for internal secret when stored in DB
  const buf = crypto.randomBytes(len);
  return buf.toString("base64url");
}


function encryptSecret(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${enc.toString("base64")}:${tag.toString("base64")}`;
}

function decryptSecret(enc) {
  const parts = String(enc || "").split(":");
  if (parts.length !== 3) throw new Error("bad_secret_format");
  const iv = Buffer.from(parts[0], "base64");
  const data = Buffer.from(parts[1], "base64");
  const tag = Buffer.from(parts[2], "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  return plain.toString("utf-8");
}


async function getJwtSecret() {
  return withDb(async (c) => {
    const r = await c.query("SELECT value FROM app_settings WHERE key='jwt_secret'");
    return r.rows[0].value;
  });
}

async function getSetting(key) {
  return withDb(async (c) => {
    const r = await c.query("SELECT value FROM app_settings WHERE key=$1", [String(key)]);
    return r.rowCount ? r.rows[0].value : null;
  });
}

async function setSetting(key, value) {
  await withDb(async (c) => {
    await c.query(
      "INSERT INTO app_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
      [String(key), String(value)]
    );
  });
}

function timingSafeEqualStr(a, b) {
  const aa = Buffer.from(String(a || ""), "utf-8");
  const bb = Buffer.from(String(b || ""), "utf-8");
  // Make lengths equal to avoid early-return side channels.
  const max = Math.max(aa.length, bb.length, 1);
  const a2 = Buffer.concat([aa, Buffer.alloc(max - aa.length)]);
  const b2 = Buffer.concat([bb, Buffer.alloc(max - bb.length)]);
  return crypto.timingSafeEqual(a2, b2) && aa.length === bb.length;
}

async function getAdminResetToken() {
  if (process.env.ADMIN_RESET_TOKEN) return String(process.env.ADMIN_RESET_TOKEN);
  return await getSetting("admin_reset_token");
}

function getToken(req) {
  return req.cookies?.icloudpd_webui_session || null;
}

async function authRequired(req, res, next) {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    const secret = await getJwtSecret();
    req.user = jwt.verify(token, secret);
    return next();
  } catch {
    return res.status(401).json({ error: "unauthorized" });
  }
}

async function adminRequired(req, res, next) {
  await authRequired(req, res, async () => {
    if (req.user?.role !== "admin") return res.status(403).json({ error: "forbidden" });
    next();
  });
}

// Routes: root routing without loops
app.get("/", async (req, res) => {
  const token = getToken(req);
  if (!token) return res.redirect("/login.html");
  try {
    const secret = await getJwtSecret();
    jwt.verify(token, secret);
    return res.redirect("/app.html");
  } catch {
    return res.redirect("/login.html");
  }
});

app.get("/login.html", async (req, res, next) => {
  // if logged in, move to app
  const token = getToken(req);
  if (!token) return next();
  try {
    const secret = await getJwtSecret();
    jwt.verify(token, secret);
    return res.redirect("/app.html");
  } catch {
    return next();
  }
});

app.get("/app.html", async (req, res, next) => {
  // if not logged in, move to login
  const token = getToken(req);
  if (!token) return res.redirect("/login.html");
  try {
    const secret = await getJwtSecret();
    jwt.verify(token, secret);
    return next();
  } catch {
    return res.redirect("/login.html");
  }
});

// Setup status
app.get("/api/setup/status", async (req, res) => {
  const count = await withDb(async (c) => {
    const r = await c.query("SELECT COUNT(*)::int AS n FROM webui_users");
    return r.rows[0].n;
  });
  res.json({ setupRequired: count === 0 });
});

app.post("/api/setup/create-admin", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });
  if (String(password).length < 10) return res.status(400).json({ error: "weak_password" });

  const count = await withDb(async (c) => {
    const r = await c.query("SELECT COUNT(*)::int AS n FROM webui_users");
    return r.rows[0].n;
  });
  if (count !== 0) return res.status(409).json({ error: "setup_already_completed" });

  const hash = bcrypt.hashSync(String(password), 12);
  await withDb(async (c) => {
    await c.query("INSERT INTO webui_users(username,password_hash,role) VALUES($1,$2,'admin')", [String(username).trim(), hash]);
  });

  res.json({ ok: true });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });

  const user = await withDb(async (c) => {
    const r = await c.query("SELECT id, username, password_hash, role FROM webui_users WHERE username=$1", [String(username).trim()]);
    return r.rowCount ? r.rows[0] : null;
  });
  if (!user) return res.status(401).json({ error: "invalid_credentials" });

  const ok = bcrypt.compareSync(String(password), user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid_credentials" });

  const secret = await getJwtSecret();
  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, secret, { expiresIn: "12h" });

  res.cookie("icloudpd_webui_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    path: "/",
    maxAge: 12 * 60 * 60 * 1000,
  });

  res.json({ ok: true, redirect: "/app.html" });
});

app.post("/api/logout", async (req, res) => {
  res.clearCookie("icloudpd_webui_session", { path: "/" });
  res.json({ ok: true });
});

// Break-glass admin password reset (requires a reset token)
// Intended for the case where the admin password is forgotten.
app.post("/api/admin/reset-password", async (req, res) => {
  const { username, token, new_password } = req.body || {};
  if (!username || !token || !new_password) return res.status(400).json({ error: "missing_fields" });
  if (String(new_password).length < 10) return res.status(400).json({ error: "weak_password" });

  const expected = await getAdminResetToken();
  if (!expected || !timingSafeEqualStr(String(token), String(expected))) {
    return res.status(401).json({ error: "invalid_token" });
  }

  const u = await withDb(async (c) => {
    const r = await c.query("SELECT id, role FROM webui_users WHERE username=$1", [String(username).trim()]);
    return r.rowCount ? r.rows[0] : null;
  });
  if (!u || u.role !== "admin") return res.status(404).json({ error: "not_found" });

  const hash = bcrypt.hashSync(String(new_password), 12);
  await withDb(async (c) => {
    await c.query("UPDATE webui_users SET password_hash=$1 WHERE id=$2", [hash, u.id]);
  });

  // Invalidate the current session cookie (if present)
  res.clearCookie("icloudpd_webui_session", { path: "/" });
  res.json({ ok: true });
});

// Admin-only helpers for reset token visibility/rotation (useful to store token somewhere safe)
app.get("/api/admin/reset-token", adminRequired, async (req, res) => {
  const token = await getSetting("admin_reset_token");
  res.json({ token: token || null, envOverride: !!process.env.ADMIN_RESET_TOKEN });
});

app.post("/api/admin/reset-token/rotate", adminRequired, async (req, res) => {
  const token = cryptoRandom(32);
  await setSetting("admin_reset_token", token);
  res.json({ token, envOverride: !!process.env.ADMIN_RESET_TOKEN });
});

// Admin-only: update / recreate iCloudPD worker containers to use the latest developer image
// Image reference can be overridden via ICLOUDPD_IMAGE; default is boredazfcuk/icloudpd:latest.
const ICLOUDPD_IMAGE_SETTING_DIGEST = "icloudpd_image_digest";
const ICLOUDPD_IMAGE_SETTING_PULLED_AT = "icloudpd_image_pulled_at";

async function pullDockerImage(imageRef) {
  return new Promise((resolve, reject) => {
    docker.pull(imageRef, (err, stream) => {
      if (err) return reject(err);
      docker.modem.followProgress(stream, (err2, output) => {
        if (err2) return reject(err2);
        resolve(output);
      });
    });
  });
}

async function inspectDockerImage(imageRef) {
  try {
    return await docker.getImage(imageRef).inspect();
  } catch {
    return null;
  }
}

app.get("/api/admin/icloudpd/image", adminRequired, async (req, res) => {
  const image = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";
  const storedDigest = await getSetting(ICLOUDPD_IMAGE_SETTING_DIGEST);
  const storedPulledAt = await getSetting(ICLOUDPD_IMAGE_SETTING_PULLED_AT);

  const info = await inspectDockerImage(image);
  const repoDigest = Array.isArray(info?.RepoDigests) && info.RepoDigests.length ? info.RepoDigests[0] : null;

  res.json({
    image,
    digest: storedDigest || repoDigest || null,
    repoDigest: repoDigest || null,
    last_pulled_at: storedPulledAt || null,
  });
});

// Helper: detect active downloads in managed icloudpd_* containers.
// IMPORTANT:
//  - The boredazfcuk/icloudpd worker keeps sync-icloud.sh running even when idle, so "process present" is NOT a valid lock.
//  - We instead treat a container as "actively downloading" if the most recent state in its logs indicates a run in progress.
//  - When the last significant state line is "Next download at ...", the container is idle and updates are allowed.
// If targetAccountId is provided, only that account container is checked (per-account lock).
function detectActiveDownloadFromLogs(logText) {
  const lines = String(logText || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  // Identify the most recent "idle" marker.
  let lastNextIdx = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (/\bNext download at\b/i.test(lines[i])) {
      lastNextIdx = i;
      break;
    }
  }

  // Identify the most recent "run" markers.
  const runMarkers = [
    /Generating list of files in iCloud/i,
    /New files detected:\s*\d+/i,
    /Processing user:/i,
    /Downloading\s+\d+/i,
    /All photos and videos have been downloaded/i,
    /Download complete/i,
    /Download ended at/i,
  ];

  let lastRunIdx = -1;
  let lastRunLine = null;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (runMarkers.some((re) => re.test(lines[i]))) {
      lastRunIdx = i;
      lastRunLine = lines[i];
      break;
    }
  }

  // If we have an idle marker and it is AFTER the last run marker, the container is idle.
  // This matches the user's requirement: unlock when the last state is "Next download at ...".
  if (lastNextIdx >= 0 && (lastRunIdx < 0 || lastNextIdx > lastRunIdx)) {
    return { active: false, reason: "idle", lastLine: lines[lastNextIdx] || null };
  }

  // If there is no idle marker visible in the log tail but we have recent run markers,
  // conservatively treat as active.
  if (lastRunIdx >= 0) {
    return { active: true, reason: "run_marker", lastLine: lastRunLine };
  }

  // Unknown state: do not block updates.
  return { active: false, reason: "unknown", lastLine: null };
}

async function listActiveDownloads(targetAccountId = null) {
  const running = await docker.listContainers({ all: false });
  const active = [];

  const targetName = (Number.isFinite(targetAccountId) && targetAccountId !== null)
    ? `icloudpd_${targetAccountId}`
    : null;

  for (const c of running) {
    const names = Array.isArray(c?.Names) ? c.Names : [];
    const raw = names.find((n) => /^\/?icloudpd_\d+$/.test(String(n || "")));
    if (!raw) continue;

    const name = String(raw).startsWith("/") ? String(raw).slice(1) : String(raw);
    if (targetName && name !== targetName) continue;

    const id = parseInt(name.split("_")[1] || "0", 10);

    try {
      // Best-effort: if logs fetch fails, do not block updates.
      const logTail = await getContainerLogs(name, 200);
      const state = detectActiveDownloadFromLogs(logTail);

      if (state.active) {
        const summary = parseSessionSummaryFromLog(logTail);
        active.push({
          id: Number.isFinite(id) ? id : null,
          name,
          lastLine: state.lastLine || null,
          nextDownloadAt: summary?.next_download_at || null,
        });
      }
    } catch {
      // Ignore errors; if we cannot inspect logs, do not block updates.
    }
  }

  return active;
}

// Lock helper. If targetAccountId is provided, only block when that account is actively downloading.
async function enforceNoDownloadsRunning(req, res, targetAccountId = null) {
  const force = (req.query?.force === "1") || (req.body && req.body.force === true);
  const active = await listActiveDownloads(targetAccountId);
  if (active.length && !force) {
    res.status(409).json({ error: "downloads_running", active });
    return false;
  }
  return true;
}

async function pullAndRecordIcloudpdImage(image) {
  await pullDockerImage(image);
  const info = await inspectDockerImage(image);
  const repoDigest = Array.isArray(info?.RepoDigests) && info.RepoDigests.length ? info.RepoDigests[0] : null;
  if (repoDigest) await setSetting(ICLOUDPD_IMAGE_SETTING_DIGEST, repoDigest);
  await setSetting(ICLOUDPD_IMAGE_SETTING_PULLED_AT, new Date().toISOString());
  return { image, digest: repoDigest || null };
}

// Admin-only: pull developer image only (no container rebuild)
app.post("/api/admin/icloudpd/pull-image", adminRequired, async (req, res) => {
  const image = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";
  const pulled = await pullAndRecordIcloudpdImage(image);
  res.json({ ok: true, pulled });
});

// Admin-only: pull image (optional) and rebuild all managed icloudpd_* containers.
app.post("/api/admin/icloudpd/rebuild-all", adminRequired, async (req, res) => {
  const image = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";

  // Lock: do not rebuild while downloads are running.
  if (!(await enforceNoDownloadsRunning(req, res))) return;

  const doPull = !(req.body && req.body.pull === false);
  const pulled = doPull ? await pullAndRecordIcloudpdImage(image) : { image, digest: null };

  const accounts = await withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts ORDER BY id");
    return r.rows;
  });

  const results = [];
  for (const acc of accounts) {
    const id = acc.id;
    try {
      await stopAndRemoveContainer(id);
      await ensureContainerForAccount(acc);
      results.push({ id, ok: true });
    } catch (e) {
      results.push({ id, ok: false, message: String(e?.message || e) });
    }
  }

  res.json({ ok: true, pulled: doPull ? pulled : null, accounts: results });
});

// Admin-only: rebuild only one selected account container (pull optional).
app.post("/api/admin/icloudpd/rebuild-account/:id", adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  // Lock (per-account): only block when THIS account is actively downloading.
  if (!(await enforceNoDownloadsRunning(req, res, id))) return;

  const image = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";
  const doPull = !(req.body && req.body.pull === false);
  const pulled = doPull ? await pullAndRecordIcloudpdImage(image) : { image, digest: null };

  const acc = await withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts WHERE id=$1", [id]);
    return r.rows[0] || null;
  });
  if (!acc) return res.status(404).json({ error: "not_found" });

  try {
    await stopAndRemoveContainer(id);
    const r = await ensureContainerForAccount(acc);
    res.json({ ok: true, pulled: doPull ? pulled : null, account: { id, ok: true, container: r } });
  } catch (e) {
    res.status(500).json({ error: "rebuild_failed", message: String(e?.message || e) });
  }
});

// Backwards-compatible endpoint: previously "update-image" meant pull + rebuild-all.
app.post("/api/admin/icloudpd/update-image", adminRequired, async (req, res) => {
  const image = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";

  if (!(await enforceNoDownloadsRunning(req, res))) return;

  const pulled = await pullAndRecordIcloudpdImage(image);

  const accounts = await withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts ORDER BY id");
    return r.rows;
  });

  const results = [];
  for (const acc of accounts) {
    const id = acc.id;
    try {
      await stopAndRemoveContainer(id);
      await ensureContainerForAccount(acc);
      results.push({ id, ok: true });
    } catch (e) {
      results.push({ id, ok: false, message: String(e?.message || e) });
    }
  }

  res.json({ ok: true, pulled, accounts: results });
});

app.get("/api/me", authRequired, async (req, res) => {
  res.json({ id: req.user.sub, username: req.user.username, role: req.user.role });
});

// Users (admin only)
app.get("/api/users", adminRequired, async (req, res) => {
  const users = await withDb(async (c) => {
    const r = await c.query("SELECT id, username, role FROM webui_users ORDER BY id");
    return r.rows;
  });
  res.json(users);
});

app.post("/api/users", adminRequired, async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });
  if (String(password).length < 10) return res.status(400).json({ error: "weak_password" });
  const hash = bcrypt.hashSync(String(password), 12);
  const r = await withDb(async (c) => {
    return c.query("INSERT INTO webui_users(username,password_hash,role) VALUES($1,$2,$3) RETURNING id, username, role",
      [String(username).trim(), hash, (role === "user" ? "user" : "admin")]
    );
  });
  res.json(r.rows[0]);
});

app.put("/api/users/:id", adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  const { password, role } = req.body || {};
  const nextRole = (role === "user" ? "user" : role === "admin" ? "admin" : null);
  const hasPassword = typeof password === "string" && password.length > 0;
  if (hasPassword && String(password).length < 10) return res.status(400).json({ error: "weak_password" });

  await withDb(async (c) => {
    await c.query("BEGIN");
    try {
      const r = await c.query("SELECT id, role FROM webui_users WHERE id=$1 FOR UPDATE", [id]);
      if (!r.rowCount) {
        await c.query("ROLLBACK");
        return res.status(404).json({ error: "not_found" });
      }
      const curRole = r.rows[0].role;

      if (nextRole && curRole === "admin" && nextRole !== "admin") {
        const ac = await c.query("SELECT COUNT(*)::int AS n FROM webui_users WHERE role='admin'");
        const admins = ac.rows[0].n;
        if (admins <= 1) {
          await c.query("ROLLBACK");
          return res.status(409).json({ error: "cannot_demote_last_admin" });
        }
      }

      const updates = [];
      const params = [];
      let p = 1;
      if (hasPassword) { updates.push(`password_hash=$${p++}`); params.push(bcrypt.hashSync(String(password), 12)); }
      if (nextRole) { updates.push(`role=$${p++}`); params.push(nextRole); }
      if (!updates.length) {
        await c.query("COMMIT");
        return res.json({ ok: true });
      }
      params.push(id);
      await c.query(`UPDATE webui_users SET ${updates.join(", ")} WHERE id=$${p}`, params);
      await c.query("COMMIT");
      return res.json({ ok: true });
    } catch (e) {
      try { await c.query("ROLLBACK"); } catch {}
      throw e;
    }
  });
});

app.delete("/api/users/:id", adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });
  await withDb(async (c) => {
    await c.query("BEGIN");
    try {
      const r = await c.query("SELECT id, role FROM webui_users WHERE id=$1 FOR UPDATE", [id]);
      if (!r.rowCount) {
        await c.query("ROLLBACK");
        return res.status(404).json({ error: "not_found" });
      }
      if (r.rows[0].role === "admin") {
        const ac = await c.query("SELECT COUNT(*)::int AS n FROM webui_users WHERE role='admin'");
        const admins = ac.rows[0].n;
        if (admins <= 1) {
          await c.query("ROLLBACK");
          return res.status(409).json({ error: "cannot_delete_last_admin" });
        }
      }
      await c.query("DELETE FROM webui_users WHERE id=$1", [id]);
      await c.query("COMMIT");
      return res.json({ ok: true });
    } catch (e) {
      try { await c.query("ROLLBACK"); } catch {}
      throw e;
    }
  });
});

// Accounts CRUD
app.get("/api/accounts", authRequired, async (req, res) => {
  const rows = await withDb(async (c) => {
    const r = await c.query("SELECT id, label, apple_id, authentication_type, container_user, user_id, group_id, download_path, synchronisation_interval, skip_created_before, skip_created_after FROM icloud_accounts ORDER BY id");
    return r.rows;
  });
  res.json(rows);
});

app.post("/api/accounts", authRequired, async (req, res) => {
  const b = req.body || {};
  const required = ["label","apple_id","apple_password","authentication_type","container_user","user_id","group_id","download_path","synchronisation_interval"];
  for (const k of required) if (!b[k] && b[k] !== 0) return res.status(400).json({ error: "missing_fields" });

  const r = await withDb(async (c) => {
    return c.query(`
      INSERT INTO icloud_accounts(label, apple_id, apple_password_enc, authentication_type, container_user, user_id, group_id, download_path, synchronisation_interval, skip_created_before, skip_created_after)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id
    `, [
      String(b.label).trim(),
      String(b.apple_id).trim(),
      encryptSecret(String(b.apple_password || "")),
      String(b.authentication_type),
      String(b.container_user).trim(),
      parseInt(b.user_id,10)||1000,
      parseInt(b.group_id,10)||1000,
      String(b.download_path).trim(),
      parseInt(b.synchronisation_interval,10)||86400,
      (b.skip_created_before ? String(b.skip_created_before).trim() : null),
      (b.skip_created_after ? String(b.skip_created_after).trim() : null),
    ]);
  });
  res.json({ ok: true, id: r.rows[0].id });
});

// Return full account configuration (excluding encrypted password)
app.get("/api/accounts/:id", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });
  const a = await withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts WHERE id=$1", [id]);
    return r.rowCount ? r.rows[0] : null;
  });
  if (!a) return res.status(404).json({ error: "not_found" });
  const has_password = !!(a.apple_password_enc && String(a.apple_password_enc).length > 0);
  delete a.apple_password_enc;
  res.json({ ...a, has_password });
});

// Update account configuration. Provide apple_password only if you want to change it.
app.put("/api/accounts/:id", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  const b = req.body || {};
  const allow = new Set([
    "label",
    "apple_id",
    "authentication_type",
    "container_user",
    "user_id",
    "group_id",
    "download_path",
    "synchronisation_interval",
    "skip_created_before",
    "skip_created_after",
    "folder_structure",
    "directory_permissions",
    "file_permissions",
    "convert_heic_to_jpeg",
    "delete_heic_jpegs",
    "command_line_options",
    "notification_days",
    "notification_type",
    "prowl_api_key",
    "pushbullet_api_key",
    "telegram_token",
    "telegram_chat_id",
  ]);

  const updates = [];
  const params = [];
  let p = 1;

  for (const k of Object.keys(b)) {
    if (!allow.has(k)) continue;
    let v = b[k];
    if (k === "user_id" || k === "group_id" || k === "synchronisation_interval" || k === "notification_days") {
      v = (v === null || v === undefined || v === "") ? null : (parseInt(v, 10) || 0);
    }
    if (typeof v === "string") v = v.trim();
    updates.push(`${k}=$${p++}`);
    params.push(v === "" ? null : v);
  }

  if (typeof b.apple_password === "string" && b.apple_password.length > 0) {
    updates.push(`apple_password_enc=$${p++}`);
    params.push(encryptSecret(String(b.apple_password)));
  }

  if (!updates.length) return res.json({ ok: true });
  params.push(id);

  const r = await withDb(async (c) => {
    return c.query(`UPDATE icloud_accounts SET ${updates.join(", ")} WHERE id=$${p}`, params);
  });

  res.json({ ok: true, updated: r.rowCount });
});

app.delete("/api/accounts/:id", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  // Delete DB row first and respond quickly; do slow Docker/filesystem cleanup async.
  await withDb(async (c) => c.query("DELETE FROM icloud_accounts WHERE id=$1", [id]));
  res.json({ ok: true });

  // Best-effort cleanup (do not block HTTP response)
  (async () => {
    await stopAndRemoveContainer(id).catch(()=>{});
    // Remove hostdata for this account if present
    try {
      const accDir = path.join(HOSTDATA_DIR, "accounts", String(id));
      await fs.promises.rm(accDir, { recursive: true, force: true });
    } catch {}
  })();
});

// Docker management
const docker = new Docker({ socketPath: "/var/run/docker.sock" });
async function getContainerInfo(containerName){
  const c = docker.getContainer(containerName);
  return await c.inspect();
}

async function getContainerLogs(containerName, tail=4000){
  // Returns stdout/stderr logs as UTF-8 string (tail lines).
  const c = docker.getContainer(containerName);
  const b = await c.logs({ stdout: true, stderr: true, tail });
  return b.toString("utf-8");
}

const ICLOUDPD_IMAGE = process.env.ICLOUDPD_IMAGE || "boredazfcuk/icloudpd:latest";

function accountContainerName(id){ return `icloudpd_${id}`; }

async function getAccount(id) {
  return withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts WHERE id=$1", [id]);
    return r.rowCount ? r.rows[0] : null;
  });
}

function parseSessionSummaryFromLog(logText){
  // Extract last occurrence of session summary lines in the log output.
  // Works with boredazfcuk/icloudpd logs that include:
  // Web cookie expires: YYYY-MM-DD @ HH:MM:SS
  // Multi-factor authentication cookie expires: YYYY-MM-DD @ HH:MM:SS
  // Days remaining until expiration: N
  // Next download at <date string>
  const lines = (logText || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  const out = {
    web_cookie_expires: null,
    mfa_cookie_expires: null,
    days_remaining: null,
    next_download_at: null,
  };

  for (const line of lines){
    let m;
    m = line.match(/Web cookie expires:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*@\s*([0-9]{2}:[0-9]{2}:[0-9]{2})/i);
    if (m) out.web_cookie_expires = `${m[1]} ${m[2]}`;
    m = line.match(/Multi-factor authentication cookie expires:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*@\s*([0-9]{2}:[0-9]{2}:[0-9]{2})/i);
    if (m) out.mfa_cookie_expires = `${m[1]} ${m[2]}`;
    m = line.match(/Days remaining until expiration:\s*([0-9]+)/i);
    if (m) out.days_remaining = parseInt(m[1], 10);
    m = line.match(/Next download at\s*(.+)$/i);
    if (m) out.next_download_at = m[1].trim();
  }

  return out;
}

function isExpiredLocal(datetimeStr){
  // datetimeStr is "YYYY-MM-DD HH:MM:SS" in container-local time.
  // We can't reliably know timezone; treat as server-local.
  if (!datetimeStr) return null;
  const s = datetimeStr.replace(" ", "T");
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return d.getTime() < Date.now();
}


function configVolumeName(id) { return `icloudpd_config_${id}`; }

function mapAuthType(v) {
  const s = String(v || "").toUpperCase();
  if (s === "2FA" || s === "MFA") return "MFA";
  return "WEB";
}

function buildIcloudpdConf(acc) {
  const lines = [];
  lines.push(`apple_id=${acc.apple_id}`);
  lines.push(`authentication_type=${mapAuthType(acc.authentication_type)}`);
  if (acc.synchronisation_interval) lines.push(`download_interval=${acc.synchronisation_interval}`);

  // docker-icloudpd's sync-icloud.sh has hidden config keys for date filtering.
  // The current image writes these keys into /config/icloudpd.conf (even though they are not documented
  // in CONFIGURATION.md). The script expects:
  //   skip_created_before=<YYYY-MM-DD>
  //   skip_created_after=<YYYY-MM-DD>
  //
  // Note: some generated configs historically included a typo "skip_created_afer".
  // To stay compatible across versions, we write both "skip_created_after" and "skip_created_afer".
  const cleanDate = (v) => {
    const s = String(v || "").trim();
    if (!s) return "";
    // Accept either YYYY-MM-DD or a full token pasted by user; keep last token.
    return s.split(/\s+/).pop();
  };

  const before = cleanDate(acc.skip_created_before);
  const after = cleanDate(acc.skip_created_after);

  if (before) lines.push(`skip_created_before=${before}`);
  if (after) {
    lines.push(`skip_created_after=${after}`);
    lines.push(`skip_created_afer=${after}`);
  }

  // Preserve any other extra flags the user wants to pass via the container's config "command_line"
  // (this is supported by docker-icloudpd).
  if (acc.command_line_options) {
    const extra = String(acc.command_line_options).trim();
    if (extra) lines.push(`command_line=${extra}`);
  }

  return lines.join("\n") + "\n";
}

async function stopAndRemoveContainer(id) {
  const name = accountContainerName(id);
  const container = docker.getContainer(name);

  // Hard timeout: Docker operations can hang if the daemon is unhealthy.
  const withTimeout = (p, ms) => Promise.race([
    p,
    new Promise((resolve) => setTimeout(resolve, ms)),
  ]);

  // Force remove also stops the container if it is running.
  try { await withTimeout(container.remove({ force: true }), 5000); } catch {}
}


async function ensureMountedMarkerHost(acc) {
  // Create the .mounted marker on the **Docker host** download path chosen in the UI.
  //
  // Important: the webui process runs *inside its own container*. Writing to acc.download_path
  // with Node's fs APIs would create the file inside the webui container filesystem unless
  // that exact host path is bind-mounted into the webui container 1:1. This can lead to a
  // false "success" (file created in-container, but not on the host).
  //
  // Therefore we always prefer a helper container with a bind mount of the host path.
  // This reliably touches the file on the host, provided the webui has access to
  // /var/run/docker.sock (already required by the app for container management).
  if (!acc?.download_path) throw new Error("download_path_missing");

  const hostPath = String(acc.download_path).trim();
  if (!hostPath) throw new Error("download_path_empty");
  if (!hostPath.startsWith("/")) {
    throw new Error("download_path_must_be_absolute");
  }

  // Preferred method: touch the marker *inside the account's icloudpd container*.
  // The container bind-mounts acc.download_path -> /home/<user>/iCloud, so creating
  // the file there guarantees it lands on the Docker host path used for downloads.
  // This avoids edge cases where a helper container bind mount is blocked by the runtime.
  if (acc?.id) {
    const name = accountContainerName(acc.id);
    const user = String(acc.container_user || "user").trim() || "user";
    const inside = `/home/${user}/iCloud/.mounted`;
    try {
      await execInContainer(name, `mkdir -p /home/${user}/iCloud && : > ${inside} && test -f ${inside}`);
      return;
    } catch {
      // Fall through to helper container.
    }
  }

  const helperImage = "alpine:3.20";

  async function pullImage(image) {
    return new Promise((resolve, reject) => {
      docker.pull(image, (err, stream) => {
        if (err) return reject(err);
        docker.modem.followProgress(stream, (err2) => {
          if (err2) return reject(err2);
          resolve();
        });
      });
    });
  }

  async function runHelperOnce() {
    const helper = await docker.createContainer({
      Image: helperImage,
      Cmd: ["sh", "-lc", "mkdir -p /mnt && : > /mnt/.mounted && test -f /mnt/.mounted"],
      HostConfig: {
        AutoRemove: true,
        Binds: [`${hostPath}:/mnt`],
      },
    });

    try {
      await helper.start();
      const result = await helper.wait();
      const code = (result?.StatusCode ?? 0);
      if (code !== 0) throw new Error(`mounted_helper_exit_${code}`);
    } finally {
      // AutoRemove should handle it, but keep a best-effort cleanup.
      try { await helper.remove({ force: true }); } catch {}
    }
  }

  try {
    await runHelperOnce();
  } catch (e) {
    // If the image is missing, pull and retry once.
    const msg = String(e?.message || e);
    if (msg.includes("No such image") || msg.includes("not found")) {
      await pullImage(helperImage);
      await runHelperOnce();
    } else {
      // Do not fall back to local fs writes; that can create a false success.
      throw e;
    }
  }
}

async function ensureContainerForAccount(acc) {
  const name = accountContainerName(acc.id);

  // Pull image best-effort (do not block)
  try { await docker.pull(ICLOUDPD_IMAGE, {}); } catch {}

  let container;
  try {
    container = docker.getContainer(name);
    await container.inspect();
  } catch {
    container = await docker.createContainer({
      name,
      Image: ICLOUDPD_IMAGE,
      Env: [
        `user=${acc.container_user}`,
        `user_id=${acc.user_id}`,
        `group_id=${acc.group_id}`,
      ],
      HostConfig: {
        RestartPolicy: { Name: "unless-stopped" },
        Binds: [
          `${acc.download_path}:/home/${acc.container_user}/iCloud`,
        ],
        Mounts: [
          { Type: "volume", Source: configVolumeName(acc.id), Target: "/config" },
        ],
      },
    });
  }

  // Start (idempotent)
  try { await container.start(); } catch {}

  // Write config into the /config volume so icloudpd sees apple_id.
  const conf = buildIcloudpdConf(acc);
  const b64 = Buffer.from(conf, "utf-8").toString("base64");
  await execInContainer(name, `echo ${b64} | base64 -d > /config/icloudpd.conf`);  // Ensure failsafe .mounted (host path marker)
  await ensureMountedMarkerHost(acc);

  // Restart so entrypoint reloads config immediately
  try { await container.restart({ t: 10 }); } catch {}

  await patchSyncScript(name);

  const info = await container.inspect();
  return { name, state: info?.State?.Status, running: !!info?.State?.Running };
}


async function patchSyncScript(containerName) {
  // Workaround: boredazfcuk/icloudpd currently builds skip-created flags with four dashes in sync-icloud.sh.
  // Patch them in-place to the correct two-dash icloudpd flags.
  const cmd = [
    "set -e",
    "p=$(command -v sync-icloud.sh 2>/dev/null || true)",
    "for f in \"$p\" /usr/local/bin/sync-icloud.sh /usr/bin/sync-icloud.sh; do",
    "  [ -n \"$f\" ] || continue",
    "  [ -f \"$f\" ] || continue",
    "  chmod u+w \"$f\" 2>/dev/null || true",
    "  # Replace both the raw token and the quoted forms used in command_line concatenation",
    "  sed -i 's/ ----skip-created-before/ --skip-created-before/g; s/ ----skip-created-after/ --skip-created-after/g; s/----skip-created-before/--skip-created-before/g; s/----skip-created-after/--skip-created-after/g' \"$f\" 2>/dev/null || true",
    "done",
  ].join("; ");
  try { await execInContainer(containerName, cmd); } catch {}
}
async function execInContainer(containerName, cmd) {
  // non-interactive exec
  const container = docker.getContainer(containerName);
  const exec = await container.exec({
    AttachStdout: true,
    AttachStderr: true,
    AttachStdin: false,
    Tty: false,
    Cmd: ["sh", "-lc", cmd],
  });
  return new Promise((resolve, reject) => {
    exec.start((err, stream) => {
      if (err) return reject(err);
      let out = "";
      stream.on("data", (d) => out += d.toString("utf-8"));
      stream.on("end", () => resolve(out));
      stream.on("error", reject);
    });
  });
}

app.post("/api/accounts/:id/ensure", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const acc = await getAccount(id);
  if (!acc) return res.status(404).json({ error: "not_found" });
  try {
    const r = await ensureContainerForAccount(acc);
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: "ensure_failed", message: String(e?.message || e) });
  }
});

app.post("/api/accounts/:id/fix-skip-dates", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  const acc = await withDb(async (c) => {
    const r = await c.query("SELECT * FROM icloud_accounts WHERE id=$1", [id]);
    return r.rows[0] || null;
  });
  if (!acc) return res.status(404).json({ error: "not_found" });

  const name = accountContainerName(id);

  const patchCmd = [
    "set -e",
    "p=/usr/local/bin/sync-icloud.sh",
    "echo \"Patching: $p\"",
    "chmod u+w \"$p\" 2>/dev/null || true",
    "sed -i \"s/ ----skip-created-before/ --skip-created-before/g; s/ ----skip-created-after/  --skip-created-after/g; s/----skip-created-before/--skip-created-before/g; s/----skip-created-after/--skip-created-after/g\" \"$p\"",
    "echo \"After patch:\"",
    "grep -n \"skip-created-before\" \"$p\" | head -n 5 || true",
    "grep -n \"skip-created-after\"  \"$p\" | head -n 5 || true",
  ].join("; ");

  let output = "";
  try {
    output = await execInContainer(name, patchCmd);
  } catch (e) {
    return res.status(500).json({ error: "exec_failed", details: String(e?.message || e) });
  }

  res.json({ ok: true, output });
});


app.post("/api/accounts/:id/restart", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const name = accountContainerName(id);
  try {
    const c = docker.getContainer(name);
    await patchSyncScript(name);
    await c.restart({ t: 10 });
    await patchSyncScript(name);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "restart_failed", message: String(e?.message || e) });
  }
});

app.post("/api/accounts/:id/mounted", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const acc = await getAccount(id);
  if (!acc) return res.status(404).json({ error: "not_found" });
  const name = accountContainerName(id);
  try {
    await ensureMountedMarkerHost(acc);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "mounted_failed", message: String(e?.message || e) });
  }
});


// WebSocket terminal (interactive via node-pty and docker exec -it)
// Supports guided initialise: if query param init=1, runs sync-icloud.sh --Initialise and auto-feeds stored password,
// then prompts the user to enter the MFA code.
const wss = new WebSocketServer({ server, path: "/ws/terminal" });

wss.on("connection", async (socket, req) => {
  let term = null;
  try {
    // Auth: verify cookie
    const cookie = req.headers.cookie || "";
    const mm = cookie.match(/icloudpd_webui_session=([^;]+)/);
    if (!mm) { socket.close(); return; }
    const secret = await getJwtSecret();
    try { jwt.verify(decodeURIComponent(mm[1]), secret); } catch { socket.close(); return; }

    const url = new URL(req.url, "http://localhost");
    const accountId = parseInt(url.searchParams.get("accountId") || "0", 10);
    const init = (url.searchParams.get("init") || "0") === "1";
    const logs = (url.searchParams.get("logs") || "0") === "1";

    if (!Number.isFinite(accountId) || accountId <= 0) { socket.send("Invalid accountId"); socket.close(); return; }

    const acc = await getAccount(accountId);
    if (!acc) { socket.send("Account not found"); socket.close(); return; }

    const name = accountContainerName(accountId);

    // Ensure container exists before terminal (best-effort)
    try { await ensureContainerForAccount(acc); } catch {}

    const dockerPath = "/usr/local/bin/docker";
    let passwordSent = false;
        let keyringConfirmed = false;
    const password = (() => {
      try { return decryptSecret(acc.apple_password_enc); } catch { return ""; }
    })();

    
if (logs) {
  term = pty.spawn(dockerPath, ["logs", "-f", "--tail", "200", name], {
    name: "xterm-color", cols: 120, rows: 30, cwd: "/", env: process.env,
  });
} else if (init) {
  term = pty.spawn(dockerPath, ["exec", "-it", name, "sync-icloud.sh", "--Initialise"], {
    name: "xterm-color", cols: 120, rows: 30, cwd: "/", env: process.env,
  });
} else {
  term = pty.spawn(dockerPath, ["exec", "-it", name, "sh"], {
    name: "xterm-color", cols: 120, rows: 30, cwd: "/", env: process.env,
  });
}

    term.onData((d) => {
  try { socket.send(d); } catch {}

  if (!init) return;

  const s = String(d);

  // 1) Auto-send iCloud password when prompted
  if (!passwordSent && password) {
    // Prefer the explicit prompt if present; otherwise fallback to generic "password" prompt.
    if (/enter\s+icloud\s+password/i.test(s) || (/password/i.test(s) && !/keyring/i.test(s) && !/validation\s+code/i.test(s))) {
      passwordSent = true;
      try { term.write(password + "\r"); } catch {}
      try { socket.send("\n[webui] Password sent.\n"); } catch {}
    }
  }

  // 2) Auto-confirm saving password into keyring
  if (!keyringConfirmed && /save\s+password\s+in\s+keyring\?/i.test(s)) {
    keyringConfirmed = true;
    try { term.write("y\r"); } catch {}
    try { socket.send("\n[webui] Confirmed keyring save (y).\n"); } catch {}
  }

  // 3) Inform user when MFA is needed
  if (/two-?step\s+authentication\s+required/i.test(s) || /validation\s+code/i.test(s)) {
    try { socket.send("\n[webui] Please enter the MFA code.\n"); } catch {}
  }
});

    socket.on("message", (msg) => {
      try { term.write(String(msg)); } catch {}
    });

    const cleanup = () => {
      try { term?.kill(); } catch {}
      term = null;
    };

    socket.on("close", cleanup);
    socket.on("error", cleanup);
  } catch {
    try { term?.kill(); } catch {}
    try { socket.close(); } catch {}
  }
});

await initDb();

server.listen(PORT, () => {
  console.log(`[icloudpd-webui] listening on :${PORT}`);
  console.log(`[icloudpd-webui] Postgres: ${DATABASE_URL.replace(/:[^:@/]+@/, ":***@")}`);
  console.log(`[icloudpd-webui] icloudpd image: ${ICLOUDPD_IMAGE}`);
});
app.get("/api/accounts/:id/session-info", authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

  const name = accountContainerName(id);

  try{
    const info = await getContainerInfo(name); // existing helper (inspect)
    const health = info?.State?.Health?.Status || info?.State?.Status || "unknown";

    let logText = "";
    try{
      logText = await getContainerLogs(name, 6000);
    }catch(e){
      // ignore log fetch failures
      logText = "";
    }

    const summary = parseSessionSummaryFromLog(logText);
    // Prefer the "Days remaining until expiration" signal from the container log to avoid timezone parsing issues.
const daysRemaining = (typeof summary.days_remaining === "number") ? summary.days_remaining : null;
const mfaExpired = (daysRemaining !== null) ? (daysRemaining <= 0) : isExpiredLocal(summary.mfa_cookie_expires);
const webExpired = (daysRemaining !== null) ? (daysRemaining <= 0) : isExpiredLocal(summary.web_cookie_expires);

    const warnings = [];
    if (health === "unhealthy"){
      warnings.push(`Warning: iCloudPD container health is unhealthy.`);
    } else if (health === "exited" || health === "dead"){
      warnings.push(`Warning: iCloudPD container is not running (${health}).`);
    }

    if (mfaExpired === true){
      warnings.push(`Warning: Multi-factor authentication cookie expired on ${summary.mfa_cookie_expires}. Run Initialise (2FA).`);
    }
    if (webExpired === true){
      warnings.push(`Warning: Web cookie expired on ${summary.web_cookie_expires}. Run Initialise (2FA).`);
    }

    res.json({
      ok: true,
      health,
      summary,
      warnings,
    });
  }catch(e){
    res.status(404).json({ error: "container_not_found", details: String(e?.message || e) });
  }
});


