#!/usr/bin/env node
import pg from "pg";
import bcrypt from "bcryptjs";

const { Client } = pg;

function die(msg){
  console.error(msg);
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length < 2){
  die("Usage: node tools/reset-admin.js <username> <new_password>");
}

const [username, newPassword] = args;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) die("DATABASE_URL is not set.");

const client = new Client({ connectionString: DATABASE_URL });

(async () => {
  await client.connect();

  const user = await client.query("SELECT id, username, role FROM webui_users WHERE username=$1", [username]);
  if (!user.rows.length){
    die(`User not found: ${username}`);
  }

  const hash = await bcrypt.hash(String(newPassword), 12);
  await client.query("UPDATE webui_users SET password_hash=$1 WHERE id=$2", [hash, user.rows[0].id]);

  console.log(`OK: password updated for ${username}`);
  await client.end();
})().catch((e) => {
  console.error("Reset failed:", e?.message || e);
  process.exit(1);
});
