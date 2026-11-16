// Independent test vectors for src/crypto.rs, from Node's own crypto (no
// Bitwarden code, no Rust). Regenerate with: node tests/vectors.js
// The user key and the IVs are random, so a rerun writes new (equally valid)
// protected_user_key / user_key / encrypted_name files.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const out = path.join(__dirname, "vectors");
fs.mkdirSync(out, { recursive: true });
const write = (name, value) => fs.writeFileSync(path.join(out, name), value + "\n");

const password = "hunter2";
const email = " Test@Example.com ".trim().toLowerCase();

// PBKDF2-SHA256 master key, salted with the normalised email.
const master = crypto.pbkdf2Sync(password, email, 5000, 32, "sha256");
write("pbkdf2_master_key", master.toString("hex"));

// Master password hash: one round of the master key, salted with the password.
write("pbkdf2_password_hash", crypto.pbkdf2Sync(master, password, 1, 32, "sha256").toString("base64"));

// HKDF-Expand only (the master key is the PRK): T(1) = HMAC(PRK, info || 0x01).
const expand = (info) =>
  crypto.createHmac("sha256", master).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const encKey = expand("enc");
const macKey = expand("mac");
write("pbkdf2_stretched", Buffer.concat([encKey, macKey]).toString("hex"));

// Argon2id: salt is SHA-256 of the email; memory in KiB.
const argonSalt = crypto.createHash("sha256").update(email).digest();
const argon = crypto.argon2Sync("argon2id", {
  message: password,
  nonce: argonSalt,
  parallelism: 4,
  tagLength: 32,
  memory: 16 * 1024,
  passes: 3,
});
write("argon2id_master_key", argon.toString("hex"));

// A type 2 EncString: AES-256-CBC + HMAC-SHA256(iv || ct).
const encString = (enc, mac, plain) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", enc, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = crypto.createHmac("sha256", mac).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${tag.toString("base64")}`;
};

const userKey = crypto.randomBytes(64);
write("user_key", userKey.toString("hex"));
write("protected_user_key", encString(encKey, macKey, userKey));
write("encrypted_name", encString(userKey.subarray(0, 32), userKey.subarray(32), Buffer.from("Ünïcode name ✓")));
