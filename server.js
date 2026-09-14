import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import { MongoClient, ObjectId } from "mongodb";

const app = express();
const port = Number(process.env.PORT || 5000);
const mongoUri = process.env.MONGO_URI;
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const allowedOrigins = (process.env.CORS_ORIGIN || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!mongoUri) {
  throw new Error("MONGO_URI est obligatoire dans .env");
}

const client = new MongoClient(mongoUri);
let db;

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowAll = allowedOrigins.includes("*");
  if (allowAll || (origin && allowedOrigins.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", allowAll ? "*" : origin);
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  return next();
});

app.use(express.json({ limit: "1mb" }));

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify({ ...payload, exp: Date.now() + 1000 * 60 * 60 * 12 }));
  const signature = crypto
    .createHmac("sha256", sessionSecret)
    .update(`${header}.${body}`)
    .digest("base64url");
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [header, body, signature] = token.split(".");
  if (!header || !body || !signature) return null;
  const expected = crypto
    .createHmac("sha256", sessionSecret)
    .update(`${header}.${body}`)
    .digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  return payload.exp > Date.now() ? payload : null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const attempt = hashPassword(password, salt).split(":")[1];
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(attempt));
}

function publicUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    invoiceCount: user.invoiceCount || 0,
    revenue: user.revenue || 0
  };
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const payload = verifyToken(auth.startsWith("Bearer ") ? auth.slice(7) : "");
  if (!payload) return res.status(401).json({ error: "Non authentifie" });
  req.user = payload;
  return next();
}

function adminRequired(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Seul l'administrateur peut gerer les comptes utilisateurs" });
  }
  return next();
}

function objectIdParam(req, res, next) {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: "Identifiant invalide" });
  }
  return next();
}

function cleanInvoice(invoice) {
  const { _id, ownerId, createdAt, updatedAt, ...rest } = invoice;
  return {
    ...rest,
    id: _id.toString(),
    ownerId: ownerId?.toString?.() || ownerId,
    createdAt,
    updatedAt
  };
}

function cleanClient(client) {
  const { _id, ownerId, createdAt, updatedAt, ...rest } = client;
  return {
    ...rest,
    id: _id.toString(),
    ownerId: ownerId?.toString?.() || ownerId,
    createdAt,
    updatedAt
  };
}

function invoiceNumberKey(number) {
  return String(number || "").trim();
}

async function highestInvoiceNumber() {
  const invoices = await db.collection("invoices").find({}, { projection: { number: 1 } }).toArray();
  return invoices.reduce((max, invoice) => {
    const numeric = String(invoice.number || "").match(/\d+/g)?.join("") || "0";
    return Math.max(max, Number(numeric));
  }, 0);
}

async function nextInvoiceNumber() {
  const counterId = "invoiceNumber";
  const highest = await highestInvoiceNumber();
  const counter = await db.collection("counters").findOne({ _id: counterId });

  if (!counter) {
    await db.collection("counters").insertOne({ _id: counterId, value: highest }).catch((error) => {
      if (error?.code !== 11000) throw error;
    });
  } else if (Number(counter.value || 0) < highest) {
    await db.collection("counters").updateOne({ _id: counterId }, { $set: { value: highest } });
  }

  const result = await db.collection("counters").findOneAndUpdate(
    { _id: counterId },
    { $inc: { value: 1 } },
    { returnDocument: "after" }
  );
  const next = Number(result?.value || highest + 1);
  return String(next).padStart(3, "0");
}

async function repairDuplicateInvoiceNumbers() {
  const invoices = await db.collection("invoices").find({}, { projection: { number: 1, createdAt: 1 } })
    .sort({ createdAt: 1, _id: 1 })
    .toArray();
  const used = new Set();
  let highest = await highestInvoiceNumber();

  for (const invoice of invoices) {
    const number = invoiceNumberKey(invoice.number);
    if (number && !used.has(number)) {
      used.add(number);
      continue;
    }

    highest += 1;
    const next = String(highest).padStart(3, "0");
    used.add(next);
    await db.collection("invoices").updateOne({ _id: invoice._id }, { $set: { number: next, updatedAt: new Date() } });
  }
}

async function ensureIndexesAndAdmin() {
  await db.collection("users").createIndex({ email: 1 }, { unique: true });
  await db.collection("invoices").createIndex({ ownerId: 1, updatedAt: -1 });
  await db.collection("invoices").createIndex({ number: 1 });
  await db.collection("clients").createIndex({ ownerId: 1, name: 1 });
  await db.collection("counters").createIndex({ _id: 1 }, { unique: true });
  await repairDuplicateInvoiceNumbers();

  const adminEmail = process.env.ADMIN_EMAIL || "admin@zmtrans.sn";
  const exists = await db.collection("users").findOne({ email: adminEmail });
  if (!exists) {
    await db.collection("users").insertOne({
      name: process.env.ADMIN_NAME || "Administrateur",
      email: adminEmail,
      role: "admin",
      passwordHash: hashPassword(process.env.ADMIN_PASSWORD || "admin12345"),
      createdAt: new Date()
    });
  }
}

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = await db.collection("users").findOne({ email: String(email || "").trim().toLowerCase() });
  if (!user || !verifyPassword(String(password || ""), user.passwordHash)) {
    return res.status(401).json({ error: "Email ou mot de passe incorrect" });
  }
  const safeUser = publicUser(user);
  return res.json({ token: signToken(safeUser), user: safeUser });
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "zmtrans-facturation-api" });
});

app.get("/api/me", authRequired, async (req, res) => {
  const user = await db.collection("users").findOne({ _id: new ObjectId(req.user.id) });
  if (!user) return res.status(401).json({ error: "Utilisateur introuvable" });
  return res.json({ user: publicUser(user) });
});

app.get("/api/users", authRequired, adminRequired, async (req, res) => {
  const users = await db.collection("users").find({}, { projection: { passwordHash: 0 } }).sort({ createdAt: -1 }).toArray();
  const stats = await db.collection("invoices").aggregate([
    { $group: { _id: "$ownerId", invoiceCount: { $sum: 1 }, revenue: { $sum: "$totalSnapshot" } } }
  ]).toArray();
  const statsByUser = new Map(stats.map((item) => [String(item._id), item]));
  return res.json({
    users: users.map((user) => publicUser({
      ...user,
      invoiceCount: statsByUser.get(String(user._id))?.invoiceCount || 0,
      revenue: statsByUser.get(String(user._id))?.revenue || 0
    }))
  });
});

app.post("/api/users", authRequired, adminRequired, async (req, res) => {
  const { name, email, password, role = "user" } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "Nom, email et mot de passe obligatoires" });
  const doc = {
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    role: role === "admin" ? "admin" : "user",
    passwordHash: hashPassword(String(password)),
    createdAt: new Date()
  };
  const result = await db.collection("users").insertOne(doc);
  return res.status(201).json({ user: publicUser({ ...doc, _id: result.insertedId }) });
});

app.put("/api/users/:id", authRequired, adminRequired, objectIdParam, async (req, res) => {
  const _id = new ObjectId(req.params.id);
  const { name, email, password, role } = req.body || {};
  const patch = {};
  if (name) patch.name = String(name).trim();
  if (email) patch.email = String(email).trim().toLowerCase();
  if (role) patch.role = role === "admin" ? "admin" : "user";
  if (password) patch.passwordHash = hashPassword(String(password));
  if (!Object.keys(patch).length) return res.status(400).json({ error: "Aucune modification" });

  const result = await db.collection("users").findOneAndUpdate(
    { _id },
    { $set: patch },
    { returnDocument: "after", projection: { passwordHash: 0 } }
  );
  if (!result) return res.status(404).json({ error: "Utilisateur introuvable" });
  return res.json({ user: publicUser(result) });
});

app.delete("/api/users/:id", authRequired, adminRequired, objectIdParam, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "Impossible de supprimer votre propre compte" });
  }
  const _id = new ObjectId(req.params.id);
  const user = await db.collection("users").findOne({ _id });
  if (!user) return res.status(404).json({ error: "Utilisateur introuvable" });
  await db.collection("invoices").updateMany(
    { ownerId: _id },
    { $set: { ownerDeleted: true, ownerName: user.name, ownerEmail: user.email } }
  );
  await db.collection("users").deleteOne({ _id });
  return res.json({ ok: true });
});

app.get("/api/users/:id/invoices", authRequired, adminRequired, objectIdParam, async (req, res) => {
  const ownerId = new ObjectId(req.params.id);
  const invoices = await db.collection("invoices").find({ ownerId }).sort({ updatedAt: -1 }).toArray();
  return res.json({ invoices: invoices.map(cleanInvoice) });
});

app.get("/api/clients", authRequired, async (req, res) => {
  const query = req.user.role === "admin" ? {} : { ownerId: new ObjectId(req.user.id) };
  const clients = await db.collection("clients").find(query).sort({ name: 1 }).toArray();
  return res.json({ clients: clients.map(cleanClient) });
});

app.post("/api/clients", authRequired, async (req, res) => {
  const {
    name,
    email = "",
    contact = "",
    phone = "",
    mobile = "",
    fax = "",
    website = "",
    address = "",
    country = "Senegal",
    street = "",
    apartment = "",
    postalCode = "",
    city = "",
    state = "",
    businessId = "",
    legalId = "",
    taxId = "",
    note = ""
  } = req.body || {};
  const cleanName = String(name || "").trim();
  if (!cleanName) return res.status(400).json({ error: "Nom du client obligatoire" });

  const now = new Date();
  const clientDoc = {
    name: cleanName,
    email: String(email || "").trim(),
    contact: String(contact || "").trim(),
    phone: String(phone || "").trim(),
    mobile: String(mobile || "").trim(),
    fax: String(fax || "").trim(),
    website: String(website || "").trim(),
    address: String(address || "").trim(),
    country: String(country || "").trim(),
    street: String(street || "").trim(),
    apartment: String(apartment || "").trim(),
    postalCode: String(postalCode || "").trim(),
    city: String(city || "").trim(),
    state: String(state || "").trim(),
    businessId: String(businessId || "").trim(),
    legalId: String(legalId || "").trim(),
    taxId: String(taxId || "").trim(),
    note: String(note || "").trim(),
    ownerId: new ObjectId(req.user.id),
    createdAt: now,
    updatedAt: now
  };
  const result = await db.collection("clients").insertOne(clientDoc);
  return res.status(201).json({ client: cleanClient({ ...clientDoc, _id: result.insertedId }) });
});

app.put("/api/clients/:id", authRequired, objectIdParam, async (req, res) => {
  const _id = new ObjectId(req.params.id);
  const query = req.user.role === "admin" ? { _id } : { _id, ownerId: new ObjectId(req.user.id) };
  const allowedFields = [
    "name",
    "email",
    "contact",
    "phone",
    "mobile",
    "fax",
    "website",
    "address",
    "country",
    "street",
    "apartment",
    "postalCode",
    "city",
    "state",
    "businessId",
    "legalId",
    "taxId",
    "note"
  ];
  const patch = { updatedAt: new Date() };
  for (const field of allowedFields) {
    if (field in (req.body || {})) {
      patch[field] = String(req.body[field] || "").trim();
    }
  }
  if (!patch.name) return res.status(400).json({ error: "Nom du client obligatoire" });

  const result = await db.collection("clients").findOneAndUpdate(
    query,
    { $set: patch },
    { returnDocument: "after" }
  );
  if (!result) return res.status(404).json({ error: "Client introuvable" });
  return res.json({ client: cleanClient(result) });
});

app.delete("/api/clients/:id", authRequired, objectIdParam, async (req, res) => {
  const _id = new ObjectId(req.params.id);
  const query = req.user.role === "admin" ? { _id } : { _id, ownerId: new ObjectId(req.user.id) };
  const result = await db.collection("clients").deleteOne(query);
  if (!result.deletedCount) return res.status(404).json({ error: "Client introuvable" });
  return res.json({ ok: true });
});

app.get("/api/invoices", authRequired, async (req, res) => {
  const query = req.user.role === "admin" ? {} : { ownerId: new ObjectId(req.user.id) };
  const invoices = await db.collection("invoices").find(query).sort({ updatedAt: -1 }).toArray();
  return res.json({ invoices: invoices.map(cleanInvoice) });
});

app.post("/api/invoices", authRequired, async (req, res) => {
  const now = new Date();
  const number = await nextInvoiceNumber();
  const duplicate = await db.collection("invoices").findOne({ number });
  if (duplicate) {
    return res.status(409).json({ error: "Numero de facture deja utilise, veuillez reessayer" });
  }
  const invoice = {
    ...req.body,
    number,
    ownerId: new ObjectId(req.user.id),
    totalSnapshot: Number(req.body?.totalSnapshot || 0),
    createdAt: now,
    updatedAt: now
  };
  delete invoice.id;
  const result = await db.collection("invoices").insertOne(invoice);
  return res.status(201).json({ invoice: cleanInvoice({ ...invoice, _id: result.insertedId }) });
});

app.put("/api/invoices/:id", authRequired, async (req, res) => {
  const _id = new ObjectId(req.params.id);
  const query = req.user.role === "admin" ? { _id } : { _id, ownerId: new ObjectId(req.user.id) };
  const patch = { ...req.body, updatedAt: new Date() };
  patch.totalSnapshot = Number(req.body?.totalSnapshot || 0);
  delete patch.id;
  delete patch._id;
  delete patch.ownerId;
  delete patch.number;
  const result = await db.collection("invoices").findOneAndUpdate(query, { $set: patch }, { returnDocument: "after" });
  if (!result) return res.status(404).json({ error: "Facture introuvable" });
  return res.json({ invoice: cleanInvoice(result) });
});

app.delete("/api/invoices/:id", authRequired, async (req, res) => {
  const _id = new ObjectId(req.params.id);
  const query = req.user.role === "admin" ? { _id } : { _id, ownerId: new ObjectId(req.user.id) };
  const result = await db.collection("invoices").deleteOne(query);
  if (!result.deletedCount) return res.status(404).json({ error: "Facture introuvable" });
  return res.json({ ok: true });
});

async function start() {
  await client.connect();
  db = client.db();
  await ensureIndexesAndAdmin();
 app.listen(port, "0.0.0.0", () => {
  console.log(`ZM Trans Facturation API running on port ${port}`);
});
}

start().catch((error) => {
  console.error(error);
  process.exit(1);
});
