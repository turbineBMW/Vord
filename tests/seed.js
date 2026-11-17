// Fill a throwaway local Vaultwarden with a test vault, encrypted the way
// Bitwarden clients do it, with Node's crypto (independent of Vord's Rust).
//
//   docker run -d --name vord-test-vw -e I_REALLY_WANT_VOLATILE_STORAGE=true \
//     -e SIGNUPS_ALLOWED=true -p 127.0.0.1:8222:80 vaultwarden/server:latest
//   node tests/seed.js [http://localhost:8222]
//
// Then: VORD_DATA_DIR=/tmp/vord-test cargo run -- login http://localhost:8222 test@vord.test
// The test account's master password is below; it only exists on that local server.
const crypto = require("crypto");

const SERVER = process.argv[2] || "http://localhost:8222";
if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(SERVER)) {
  throw new Error("seed.js only talks to a local test server");
}
const EMAIL = "test@vord.test";
const PASSWORD = "vord test password 1";
const KDF = { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }; // Argon2id

const masterKey = crypto.argon2Sync("argon2id", {
  message: PASSWORD,
  nonce: crypto.createHash("sha256").update(EMAIL).digest(),
  parallelism: KDF.kdfParallelism,
  tagLength: 32,
  memory: KDF.kdfMemory * 1024,
  passes: KDF.kdfIterations,
});
const passwordHash = crypto.pbkdf2Sync(masterKey, PASSWORD, 1, 32, "sha256").toString("base64");
const expand = (info) =>
  crypto.createHmac("sha256", masterKey).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const stretched = { enc: expand("enc"), mac: expand("mac") };

const split = (k) => ({ enc: k.subarray(0, 32), mac: k.subarray(32) });
const enc = (key, plain) => {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", key.enc, iv);
  const ct = Buffer.concat([c.update(Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain))), c.final()]);
  const mac = crypto.createHmac("sha256", key.mac).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
};

const userKeyBytes = crypto.randomBytes(64);
const userKey = split(userKeyBytes);
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicDer = publicKey.export({ type: "spki", format: "der" });
const privateDer = privateKey.export({ type: "pkcs8", format: "der" });

async function call(method, path, body, token, form) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    payload = new URLSearchParams(body).toString();
  } else if (body) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(SERVER + path, { method, headers, body: payload });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

(async () => {
  // Vaultwarden without SMTP hands the verification token straight back.
  const verify = await fetch(SERVER + "/identity/accounts/register/send-verification-email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, name: "Vord Test", receiveMarketingEmails: false }),
  });
  const emailVerificationToken = (await verify.text()).trim();
  await call("POST", "/identity/accounts/register/finish", {
    email: EMAIL,
    emailVerificationToken,
    masterPasswordHash: passwordHash,
    masterPasswordHint: null,
    userSymmetricKey: enc(stretched, userKeyBytes),
    userAsymmetricKeys: { publicKey: publicDer.toString("base64"), encryptedPrivateKey: enc(userKey, privateDer) },
    ...KDF,
  });
  const tokens = await call(
    "POST",
    "/identity/connect/token",
    {
      grant_type: "password",
      username: EMAIL,
      password: passwordHash,
      scope: "api offline_access",
      client_id: "web",
      deviceType: "9",
      deviceIdentifier: crypto.randomUUID(),
      deviceName: "seed",
    },
    null,
    true,
  );
  const token = tokens.access_token;
  const userId = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).sub;

  const folder = async (name) => (await call("POST", "/api/folders", { name: enc(userKey, name) }, token)).id;
  const work = await folder("Work");
  const personal = await folder("Personal");

  const cipher = (key, c) => ({
    encryptedFor: userId,
    type: c.type,
    folderId: c.folderId ?? null,
    organizationId: c.organizationId ?? null,
    favorite: !!c.favorite,
    reprompt: c.reprompt ?? 0,
    name: enc(key, c.name),
    notes: c.notes ? enc(key, c.notes) : null,
    fields: (c.fields || []).map((f) => ({ type: f.type, name: enc(key, f.name), value: enc(key, f.value), linkedId: null })),
    login: c.login
      ? {
          username: c.login.username ? enc(key, c.login.username) : null,
          password: c.login.password ? enc(key, c.login.password) : null,
          totp: c.login.totp ? enc(key, c.login.totp) : null,
          uris: (c.login.uris || []).map((u) => ({ uri: enc(key, u), match: null })),
        }
      : null,
    card: c.card ? Object.fromEntries(Object.entries(c.card).map(([k, v]) => [k, enc(key, v)])) : null,
    identity: c.identity ? Object.fromEntries(Object.entries(c.identity).map(([k, v]) => [k, enc(key, v)])) : null,
    secureNote: c.type === 2 ? { type: 0 } : null,
    sshKey: c.sshKey ? Object.fromEntries(Object.entries(c.sshKey).map(([k, v]) => [k, enc(key, v)])) : null,
  });
  const add = (c) => call("POST", "/api/ciphers", cipher(userKey, c), token);

  // An attachment as Bitwarden's apps make one: a key of its own, sealed
  // with the item's key; the file is the type byte 2, IV, MAC, ciphertext.
  const attach = async (cipherId, key, name, contents) => {
    const fileKey = crypto.randomBytes(64);
    const k = split(fileKey);
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv("aes-256-cbc", k.enc, iv);
    const ct = Buffer.concat([c.update(contents), c.final()]);
    const mac = crypto.createHmac("sha256", k.mac).update(Buffer.concat([iv, ct])).digest();
    const data = Buffer.concat([Buffer.from([2]), iv, mac, ct]);
    const fileName = enc(key, name);
    const slot = await call("POST", `/api/ciphers/${cipherId}/attachment/v2`, { key: enc(key, fileKey), fileName, fileSize: data.length, adminRequest: false }, token);
    const form = new FormData();
    form.append("data", new Blob([data]), fileName);
    const res = await fetch(`${SERVER}/api/ciphers/${cipherId}/attachment/${slot.attachmentId ?? slot.AttachmentId}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    if (!res.ok) throw new Error(`attachment upload: ${res.status} ${await res.text()}`);
  };

  const github = await add({
    type: 1, folderId: work, favorite: true, name: "GitHub",
    login: { username: "octocat", password: "gh-Pa55word!", totp: "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", uris: ["https://github.com/login"] },
    fields: [{ type: 0, name: "Recovery email", value: "octo@example.com" }, { type: 1, name: "PIN", value: "4321" }, { type: 2, name: "Admin", value: "true" }],
  });
  await attach(github.id ?? github.Id, userKey, "recovery-codes.txt", "1111-2222\n3333-4444\n");
  await add({ type: 1, folderId: work, name: "Basecamp", login: { username: "me@example.com", password: "bc-secret", uris: ["https://launchpad.37signals.com"] } });
  await add({ type: 1, folderId: personal, name: "Netflix", reprompt: 1, login: { username: "family@example.com", password: "n3tfl1x", uris: ["netflix.com"] } });
  await add({ type: 1, name: "Router admin", login: { username: "admin", password: "hunter2", uris: ["http://192.168.1.1"] }, notes: "Model AX-3000\nReset button on the back." });
  await add({ type: 1, name: "Steam", login: { username: "gamer", password: "pw", totp: "steam://JBSWY3DPEHPK3PXP", uris: ["https://store.steampowered.com"] } });
  await add({ type: 2, folderId: personal, name: "Wi-Fi at the cabin", notes: "SSID: Cabin\nPassword: pinecones-and-coffee" });
  await add({
    type: 3, folderId: personal, favorite: true, name: "Visa",
    card: { cardholderName: "Vord Test", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2029", code: "123" },
  });
  await add({
    type: 4, name: "Me",
    identity: { title: "Mx", firstName: "Vord", lastName: "Test", email: "me@example.com", phone: "+1 555 0100", address1: "1 Rune Road", city: "Uppsala", postalCode: "75310", country: "SE", passportNumber: "X1234567" },
  });
  await add({
    type: 5, name: "Build server",
    sshKey: { privateKey: "not a real key: test fixture for the private key field", publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample vord@test", keyFingerprint: "SHA256:qN7Yk2rT0wExampleFingerprint" },
  });
  const trashed = await add({ type: 1, name: "Old forum account", login: { username: "olduser", password: "old" } });
  await call("PUT", `/api/ciphers/${trashed.id}/delete`, null, token);

  // An organisation, its key sealed to our own public key (RSA-OAEP SHA-1),
  // with one collection and one shared login.
  const orgKeyBytes = crypto.randomBytes(64);
  const orgKey = split(orgKeyBytes);
  const sealed = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, orgKeyBytes);
  const orgKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const org = await call("POST", "/api/organizations", {
    name: "Family",
    billingEmail: EMAIL,
    collectionName: enc(orgKey, "Shared logins"),
    key: `4.${sealed.toString("base64")}`,
    keys: {
      publicKey: orgKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      encryptedPrivateKey: enc(orgKey, orgKeys.privateKey.export({ type: "pkcs8", format: "der" })),
    },
    planType: 0,
  }, token);
  const collections = await call("GET", `/api/organizations/${org.id}/collections`, null, token);
  const collectionId = (collections.data || collections.Data)[0].id ?? (collections.data || collections.Data)[0].Id;
  // An item with its own key, sealed with the organisation key.
  const itemKeyBytes = crypto.randomBytes(64);
  const shared = cipher(split(itemKeyBytes), {
    type: 1, organizationId: org.id, name: "Disney+",
    login: { username: "family@example.com", password: "mouse-ears", uris: ["https://www.disneyplus.com"] },
  });
  shared.key = enc(orgKey, itemKeyBytes);
  await call("POST", "/api/ciphers/create", { cipher: shared, collectionIds: [collectionId] }, token);

  console.log(`seeded ${EMAIL} on ${SERVER}`);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
