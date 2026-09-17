# Secure authentication demo

This is a local login/signup application built with Express and SQLite. It uses parameterized SQL queries, salted `scrypt` password hashes, opaque hashed session tokens, strict cookies, rate limiting, security headers, bounded JSON input, generic authentication errors, and a small SQL-injection resistance test suite.

## Run

```powershell
npm install
npm test
npm start
```

Open <http://localhost:3000>.

## CI/CD

GitHub Actions runs tests on Node.js 20 and 22, audits production dependencies, and builds the application container on pushes to `main`. The CD workflow publishes the image to GitHub Container Registry:

```text
ghcr.io/rhaaghavans/secure-auth-demo:latest
```

The image stores SQLite data in `/app/data`; mount a persistent volume there for deployments. The workflow requires no custom secret because it uses the repository-provided `GITHUB_TOKEN`.

## Security and OSINT/privacy measures

- Do not expose `data/auth.sqlite` or `.env` publicly; both are ignored by Git.
- Set `NODE_ENV=production` behind HTTPS so cookies receive the `Secure` attribute.
- Keep dependencies updated and run `npm audit` before deployment.
- Store only the minimum account data; this app intentionally stores email and password hash only.
- Avoid logging passwords, session tokens, raw request bodies, or unnecessary IP/device data.
- Review public DNS, repository history, exposed files, certificate transparency, and breach notifications only for systems you own or are explicitly authorized to assess.
- For a real deployment, add CSRF protection for state-changing browser requests, email verification, password reset with one-time expiring tokens, MFA, centralized secret management, database backups, alerting, and a reverse proxy with HTTPS.

The included tests exercise authorized defensive checks against this local app. They do not attack external systems.
