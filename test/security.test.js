import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

let server;
let baseUrl;
let app;
let db;

test.before(async () => {
  process.env.NODE_ENV = "test";
  ({ app, db } = await import("../src/server.js"));
  server = http.createServer(app);
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => {
  db.close();
  server.close();
});

async function request(path, options = {}) {
  return fetch(`${baseUrl}${path}`, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
}

test("rejects SQL injection payloads without bypassing authentication", async () => {
  const response = await request("/api/login", {
    method: "POST",
    body: JSON.stringify({ email: "' OR 1=1 --", password: "not-a-real-password" })
  });
  assert.equal(response.status, 401);
});

test("stores passwords as salted hashes and supports valid authentication", async () => {
  const email = `test-${Date.now()}@example.com`;
  const password = "correct horse battery staple";
  const signup = await request("/api/signup", {
    method: "POST",
    body: JSON.stringify({ email, password })
  });
  assert.equal(signup.status, 201);
  const row = db.prepare("SELECT password_hash FROM users WHERE email = ?").get(email);
  assert.ok(row.password_hash.includes(":"));
  assert.ok(!row.password_hash.includes(password));
  const login = await request("/api/login", {
    method: "POST",
    body: JSON.stringify({ email, password })
  });
  assert.equal(login.status, 200);
});

test("enforces password length and avoids account enumeration", async () => {
  const weak = await request("/api/signup", {
    method: "POST",
    body: JSON.stringify({ email: "weak@example.com", password: "short" })
  });
  assert.equal(weak.status, 400);
  const missing = await request("/api/login", {
    method: "POST",
    body: JSON.stringify({ email: "missing@example.com", password: "correct horse battery staple" })
  });
  assert.equal(missing.status, 401);
  assert.deepEqual(await missing.json(), { error: "Invalid email or password." });
});
