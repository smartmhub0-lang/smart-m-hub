# Environment Strategy

## Environments

| Environment | Purpose | Data |
|---|---|---|
| Development | Local feature work | Local or disposable database. |
| Staging | Production-like validation | Isolated staging database/storage/cache. |
| Production | Live schools | Managed database/storage/cache with backups. |

## Required Production Variables

- `APP_ENV=production`
- `MONGO_URL` — the Atlas URI, for example `mongodb+srv://URL_ENCODED_USERNAME:URL_ENCODED_PASSWORD@CLUSTER.mongodb.net/?retryWrites=true&w=majority&authSource=admin`. The username and password must be URI-encoded; Atlas database users authenticate against `admin`.
- `DB_NAME` — the application database name, for example `smart_m_hub_beta`. Do not use the URI path to select it.
- `SECRET_KEY`
- `ALLOWED_ORIGINS` or `ALLOWED_ORIGIN_REGEX`
- `FRONTEND_URL`

The backend validates these during startup. Development remains backward-compatible with local defaults.

## Secrets

Secrets can be supplied directly through environment variables or mounted secret files:

- `SECRET_KEY_FILE`
- `MONGO_URL_FILE`
- `OPENAI_API_KEY_FILE`
- `STRIPE_API_KEY_FILE`

Use a managed secret store in production, such as cloud secret manager, Kubernetes secrets, Docker secrets, or a vault service.

## Transactional Email

Set `EMAIL_PROVIDER=smtp` with `EMAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, and optionally `SMTP_USERNAME` and `SMTP_PASSWORD`. Use `SMTP_USE_TLS=true` for STARTTLS (typically port 587), or `SMTP_USE_SSL=true` for implicit TLS (typically port 465), but never both. Alternatively set `EMAIL_PROVIDER=sendgrid` with `EMAIL_FROM` and `EMAIL_API_KEY` (and optionally `EMAIL_API_URL`).

After the provider is configured, set `SUPER_ADMIN_WELCOME_EMAIL_ENABLED=true` for one deployment to send the owner welcome email. The backend records provider acceptance in `system_email_events`, so later restarts do not resend it. Set the flag back to `false` after the test. Keep `SMTP_PASSWORD` and `EMAIL_API_KEY` only in the Render secret environment; never commit them.

## Environment Isolation

Staging and production must not share:

- MongoDB databases.
- Object storage buckets.
- Cache instances.
- Payment callback URLs.
- JWT secret keys.
