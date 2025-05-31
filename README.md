# authsome

NestJS + Fastify + Prisma authentication backend

---

## Overview

- **TypeScript/Node.js (Node 24)**
- **NestJS (Fastify platform)**
- **Prisma ORM/PostgreSQL**
- Email/password authentication
- Google/Apple OAuth authentication
- FIDO2/Passkey (WebAuthn) support
- JWT/refresh token management
- High type safety, strict ESLint, high test coverage
- Fastify-specific types, strict DTO validation
- CI/CD, automated testing, automated migration recommended

---

## About frontend

The `frontend/` directory is a sample web client (SPA) for interacting with the authsome backend API.

- **Main purpose**: To provide UI examples and verify the operation of authentication APIs (email/password, OAuth, Passkey) and user management APIs
- **Tech stack**: **Static HTML/JavaScript demo** (see `frontend/public/index.html` and `script.js`). _Note: Not React/Vite, but a simple static SPA for demonstration._
- **API integration**: Calls `/auth/*` endpoints via fetch in `script.js`.
- **Auth flow**: Cookie-based JWT/refresh token management, OAuth redirect, Passkey/WebAuthn support

### Usage

```bash
cd frontend
pnpm install
pnpm run dev
```

- The frontend will start at `http://localhost:8080` (see Docker setup below)
- The backend (authsome) must be running at `http://localhost:3000`
- **API server URL is set in `frontend/public/script.js` as `API_BASE_URL`**
- For Docker, both frontend/backend are started together (see below)

### Main features

- User registration/login (email/password)
- Google/Apple OAuth authentication
- Passkey (FIDO2/WebAuthn) registration/login
- Profile and linked ID management
- API response display and error handling examples

### Example of backend integration

```js
// Example: email/password login
fetch(`${API_BASE_URL}/auth/login/email-password`, {
  method: 'POST',
  credentials: 'include', // Send cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

- For Passkey/WebAuthn, see also client SDKs like `@simplewebauthn/browser`
- For OAuth, implement redirect URL and callback handler

### Build & Deploy

```bash
pnpm run build
# Static files will be output to dist/
```

- In production, serve `frontend/dist` as static files with Nginx, etc., and reverse proxy API to the backend
- Pay attention to CORS and Cookie secure/sameSite settings

---

## Setup

```bash
# Node.js 24 recommended (use mise, nvm, etc.)
pnpm install

# Create .env file (example)
pnpm run gen:jwt-secret-env # Recommended: auto-generate .env and JWT secrets
# or
cp .env.example .env
```

- **mise (https://mise.jdx.dev/) is recommended for managing Node.js, pnpm, Prisma, TypeScript, Postgres versions. See `mise.toml` for required versions.**
- PostgreSQL is required (for local use, `docker-compose up -d` is recommended)
- DB schema is managed in `prisma/schema.prisma`
- Set DB connection, JWT secrets, OAuth credentials, etc. in `.env`

---

## Docker Compose (Recommended for local dev)

```bash
docker-compose up -d
```

- Starts backend (NestJS), frontend (static demo), and PostgreSQL DB all at once
- Frontend is served at `http://localhost:8080`, backend API at `http://localhost:3000`
- `.env` is automatically loaded for both backend and frontend
- To stop: `docker-compose down`

---

## OAuth Credential Acquisition

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials) and create/select a project
2. Go to "Credentials" → "Create OAuth 2.0 Client ID"
3. Application type: "Web application"
4. Add `http://localhost:3000/api/auth/google/callback` etc. to authorized redirect URIs
5. Set the issued "Client ID" and "Client Secret" to `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` in `.env`

### Apple OAuth

1. Create a Services ID in [Apple Developer](https://developer.apple.com/account/resources/identifiers/list/serviceId)
2. Issue Key ID, Team ID, and P8 private key
3. Set `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY` in `.env` (P8 should be a single line)

---

## JWT Secret Generation

- For security, use sufficiently long random strings for `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`.
- Example: You can automatically generate and set safe secrets in .env with the following command:

```sh
pnpm run gen:jwt-secret-env
```

- If `.env` does not exist, it will be generated from `.env.example`, and the values for `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET` will be overwritten with secure random values.
- If `.env` already exists, the relevant lines will be safely overwritten.

---

## Development & Operations

- **Hot reload**: `pnpm run start:dev` for automatic restart
- **ESLint/Prettier**: Strict type and format checks
- **Testing**: Full support for unit/E2E/coverage
- **Prisma**: Automated migration and type generation
- **Fastify**: Fast, type-safe API server
- **CI/CD**: Automate linting/testing/builds

---

## Main Scripts

- Development server: `pnpm run start:dev`
- Production build: `pnpm run build && pnpm run start:prod`
- Lint: `pnpm run lint`
- Format: `pnpm run format`
- Unit test: `pnpm run test`
- E2E test: `pnpm run test:e2e`
- Coverage: `pnpm run test:cov`
- Prisma migration: `pnpm exec prisma migrate dev`
- Prisma type generation: `pnpm exec prisma generate`

---

## API Endpoint Examples

### Email/Password Authentication

- `POST /auth/register/email-password` : Register
- `POST /auth/login/email-password` : Login
- `POST /auth/logout` : Logout
- `POST /auth/refresh-tokens` : Refresh tokens

### OAuth Authentication

- `GET /auth/google` : Start Google authentication
- `GET /auth/google/callback` : Google auth callback
- `GET /auth/apple` : Start Apple authentication
- `POST /auth/apple/callback` : Apple auth callback

### Passkey (FIDO2)

- `POST /auth/passkey/register/start` : Get registration options
- `POST /auth/passkey/register/finish` : Complete registration
- `POST /auth/passkey/login/start` : Get login options
- `POST /auth/passkey/login/finish` : Complete login
- `GET /auth/passkey/credentials` : List registered passkeys
- `DELETE /auth/passkey/credentials/:id` : Delete passkey

### Profile & ID Management

- `GET /auth/profile` : Get profile
- `GET /auth/identities` : List linked IDs
- `DELETE /auth/identities/:id` : Delete linked ID

---

## Testing & Coverage

```bash
pnpm run test        # Unit tests
pnpm run test:e2e    # E2E tests
pnpm run test:cov    # Coverage
```

- Full support for unit/E2E/coverage with Jest
- Strict type-safe tests in files like `src/auth/auth.controller.spec.ts`
- E2E tests in `test/app.e2e-spec.ts`
- Coverage output as HTML in `coverage/`

---

## Security & Operations Tips

- JWT/Cookie: Set httpOnly, secure, sameSite, etc. strictly
- Manage secrets in .env (e.g., JWT_SECRET, DB connection, OAuth credentials)
- **Never commit `.env` or secrets to git**
- Store Apple OAuth P8 keys and other credentials securely
- Fastify only, strict ESLint/type checks
- Automate Prisma migration/type generation
- Enable Fastify logger in production
- Set DB connection pool and health checks as needed
- Review CORS, Cookie, and CSRF settings for your deployment

---

## FAQ & Troubleshooting

### Q. Tests fail

- Check DB state and `.env` settings
- Re-run Prisma migration/type generation
- If using Docker, ensure all containers are healthy

### Q. OAuth/Passkey authentication does not work

- Make sure Google/Apple OAuth credentials and WebAuthn RP_ID/ORIGIN are set correctly in `.env`
- Also check browser/client behavior
- For OAuth, ensure redirect URIs match those registered in Google/Apple console

### Q. Docker containers fail to start

- Check for port conflicts (3000, 8080, 5432)
- Ensure Docker Desktop or compatible runtime is running
- Check logs with `docker-compose logs`

### Q. API requests from frontend fail (CORS or 401)

- Confirm `API_BASE_URL` in `frontend/public/script.js` matches backend URL
- Check CORS and Cookie settings in backend

---

## Contributing & Development Tips

- Automate lint/format/test in CI
- Ensure type safety and tests for DTOs/services/controllers
- Check test/coverage/ESLint pass before PR
- Contributions/issues/PRs welcome!

---

## References

- [NestJS Official](https://docs.nestjs.com/)
- [Fastify Official](https://www.fastify.io/docs/latest/)
- [Prisma Official](https://www.prisma.io/docs/)
- [SimpleWebAuthn (FIDO2)](https://simplewebauthn.dev/)
- [pnpm Official](https://pnpm.io/)

---

## License

MIT

---
