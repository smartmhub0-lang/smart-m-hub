# Deployment Notes

## Deployment Artifacts

- API image: `backend/Dockerfile`
- Worker image: `backend/Dockerfile.worker`
- Main frontend image: `frontend/Dockerfile`
- Super-admin image: `super-admin-dashboard/Dockerfile`
- Compose template: `docker-compose.production.example.yml`
- CI workflow: `.github/workflows/ci.yml`

## Required Production Configuration

- `APP_ENV=production`
- `MONGO_URL` — an Atlas URI using URI-encoded credentials and `authSource=admin`, such as `mongodb+srv://URL_ENCODED_USERNAME:URL_ENCODED_PASSWORD@CLUSTER.mongodb.net/?retryWrites=true&w=majority&authSource=admin`.
- `DB_NAME` — the application database name, such as `smart_m_hub_beta`.
- `SECRET_KEY`
- `ALLOWED_ORIGINS` or `ALLOWED_ORIGIN_REGEX`
- `FRONTEND_URL`

Secrets can also be supplied through `*_FILE` variables for secret-store mounts.

## Health Gates

- Use `/api/health` for liveness.
- Use `/api/ready` for traffic routing and rollout gates.

## Rollback

Use immutable image tags. Roll back API, worker, and frontend artifacts independently. Prefer forward-fix database changes unless a downgrade script has been verified in staging.
