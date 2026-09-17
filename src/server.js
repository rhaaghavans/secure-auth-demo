import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const dataDir = path.join(rootDir, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "auth.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionTtlMs = Number(process.env.SESSION_TTL_HOURS || 8) * 60 * 60 * 1000;

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  referrerPolicy: { policy: "no-referrer" }
}));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(rootDir, "public"), { extensions: ["html"] }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many authentication attempts. Try again later." }
});

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${derivedKey.toString("hex")}`;
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(":");
  if (!saltHex || !hashHex) return false;
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), 64);
  const expected = Buffer.from(hashHex, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function validEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 12 && password.length <= 128;
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure}`);
}

function readCookie(req, name) {
  const cookies = req.headers.cookie?.split(";").map((item) => item.trim()) || [];
  const entry = cookies.find((item) => item.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : null;
}

function currentUser(req) {
  const token = readCookie(req, "session");
  if (!token) return null;
  const row = db.prepare(`
    SELECT users.id, users.email
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(tokenHash(token), Date.now());
  return row || null;
}

app.post("/api/signup", authLimiter, (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = req.body?.password;
  if (!validEmail(email) || !validPassword(password)) {
    return res.status(400).json({ error: "Use a valid email and a password of at least 12 characters." });
  }

  try {
    const result = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email, hashPassword(password));
    const token = crypto.randomBytes(32).toString("base64url");
    db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
      .run(tokenHash(token), result.lastInsertRowid, Date.now() + sessionTtlMs);
    setSessionCookie(res, token);
    return res.status(201).json({ user: { email } });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "An account with that email already exists." });
    }
    throw error;
  }
});

app.post("/api/login", authLimiter, (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = req.body?.password;
  const user = db.prepare("SELECT id, email, password_hash FROM users WHERE email = ?").get(email);
  if (!user || !validPassword(password) || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  const token = crypto.randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .run(tokenHash(token), user.id, Date.now() + sessionTtlMs);
  setSessionCookie(res, token);
  return res.json({ user: { email: user.email } });
});

app.post("/api/logout", (req, res) => {
  const token = readCookie(req, "session");
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash(token));
  res.setHeader("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  res.status(204).end();
});

app.get("/api/me", (req, res) => {
  const user = currentUser(req);
  return user ? res.json({ user }) : res.status(401).json({ error: "Not authenticated." });
});

app.use((error, _req, res, _next) => {
  console.error("Unhandled request error", error);
  res.status(500).json({ error: "Internal server error." });
});

export { app, db };

if (process.env.NODE_ENV !== "test") {
  app.listen(port, () => console.log(`Secure auth app listening on http://localhost:${port}`));
}
