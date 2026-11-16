// Two-step login on the local test server from seed.js. Email codes go to a
// Mailpit beside Vaultwarden (see CLAUDE.md for the containers).
//
//   node tests/two-factor.js enable   turn on authenticator and email 2FA
//   node tests/two-factor.js totp     the authenticator code now
//   node tests/two-factor.js mail     the newest code Mailpit caught
//
// The authenticator secret is kept in tests/.totp-secret (git-ignored).
// Vaultwarden won't take the same TOTP code twice, so wait for a new one
// between logins.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SERVER = "http://localhost:8222";
const MAILPIT = "http://127.0.0.1:8025";
const EMAIL = "test@vord.test";
const PASSWORD = "vord test password 1"; // seed.js's; exists only on the local server
const SECRET_FILE = path.join(__dirname, ".totp-secret");

const masterKey = crypto.argon2Sync("argon2id", {
  message: PASSWORD,
  nonce: crypto.createHash("sha256").update(EMAIL).digest(),
  parallelism: 4,
  tagLength: 32,
  memory: 64 * 1024,
  passes: 3,
});
const hash = crypto.pbkdf2Sync(masterKey, PASSWORD, 1, 32, "sha256").toString("base64");

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of text.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totp(secret) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = crypto.createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[19] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1e6).padStart(6, "0");
}

const savedSecret = () => (fs.existsSync(SECRET_FILE) ? fs.readFileSync(SECRET_FILE, "utf8").trim() : null);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const nextTotpWindow = () => pause(30000 - (Date.now() % 30000) + 1000);

async function call(method, route, body, token) {
  const res = await fetch(SERVER + route, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${route}: ${res.status} ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

async function mailCode() {
  const list = await (await fetch(`${MAILPIT}/api/v1/messages`)).json();
  if (!list.messages?.length) throw new Error("Mailpit has no mail");
  const message = await (await fetch(`${MAILPIT}/api/v1/message/${list.messages[0].ID}`)).json();
  const code = message.Text.match(/\b\d{6}\b/);
  if (!code) throw new Error("no code in the newest mail");
  return code[0];
}

async function login() {
  const form = new URLSearchParams({
    grant_type: "password",
    username: EMAIL,
    password: hash,
    scope: "api offline_access",
    client_id: "web",
    deviceType: "9",
    deviceIdentifier: crypto.randomUUID(),
    deviceName: "two-factor.js",
  });
  const secret = savedSecret();
  if (secret) {
    form.set("twoFactorProvider", "0");
    form.set("twoFactorToken", totp(secret));
  }
  const res = await fetch(SERVER + "/identity/connect/token", {
    method: "POST",
    body: form,
    headers: { "Auth-Email": Buffer.from(EMAIL).toString("base64url") },
  });
  const body = await res.json();
  if (!body.access_token) throw new Error(`login: ${JSON.stringify(body).slice(0, 200)}`);
  return body.access_token;
}

async function enable() {
  fs.rmSync(SECRET_FILE, { force: true });
  let token = await login();
  // Newer Vaultwarden hands out a userVerificationToken to send back.
  const auth = await call("POST", "/api/two-factor/get-authenticator", { masterPasswordHash: hash }, token);
  const key = auth.authenticator?.key ?? auth.key;
  const verify = auth.userVerificationToken;
  await call("POST", "/api/two-factor/authenticator", { key, token: totp(key), masterPasswordHash: hash, userVerificationToken: verify }, token);
  fs.writeFileSync(SECRET_FILE, key, { mode: 0o600 });
  console.log("authenticator on");

  await nextTotpWindow();
  token = await login();
  const email = await call("POST", "/api/two-factor/get-email", { masterPasswordHash: hash }, token);
  const emailVerify = email.userVerificationToken;
  await call("POST", "/api/two-factor/send-email", { email: EMAIL, masterPasswordHash: hash, userVerificationToken: emailVerify }, token);
  await pause(1500);
  await call("PUT", "/api/two-factor/email", { email: EMAIL, token: await mailCode(), masterPasswordHash: hash, userVerificationToken: emailVerify }, token);
  console.log("email on");
}

(async () => {
  switch (process.argv[2]) {
    case "enable":
      return enable();
    case "totp":
      if (!savedSecret()) throw new Error("run `enable` first");
      return console.log(totp(savedSecret()));
    case "mail":
      return console.log(await mailCode());
    default:
      throw new Error("usage: node tests/two-factor.js enable|totp|mail");
  }
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
