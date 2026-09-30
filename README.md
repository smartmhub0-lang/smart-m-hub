# Smart M Hub

Smart M Hub is a secure school operations platform for administration, academics, finance, communication, approvals, and student services.

## Project Structure

- `backend/` - FastAPI backend and MongoDB data layer.
- `frontend/` - School-facing React frontend.
- `super-admin-dashboard/` - Platform-owner dashboard.
- `docs/` - Implementation and audit documentation.

## Required Environment Variables

Backend:

```env
APP_ENV=production
# Use the Atlas connect-string host. URL-encode username and password values.
MONGO_URL=mongodb+srv://URL_ENCODED_USERNAME:URL_ENCODED_PASSWORD@CLUSTER.mongodb.net/?retryWrites=true&w=majority&authSource=admin
DB_NAME=smart_m_hub_beta
SECRET_KEY=replace-with-a-long-random-secret
ALLOWED_ORIGINS=https://school.example.com,https://admin.example.com
FRONTEND_URL=https://school.example.com
LOGIN_MAX_ATTEMPTS=5
LOGIN_LOCKOUT_MINUTES=15
PASSWORD_MIN_LENGTH=8
MAX_UPLOAD_MB=5
```

School frontend:

```env
REACT_APP_BACKEND_URL=https://api.example.com
```

Super admin dashboard:

```env
VITE_API_BASE_URL=https://api.example.com/api/platform
```

Use the `.env.example` files in each app folder as templates. Do not commit real `.env` files.

## Local Development

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --reload --host 127.0.0.1 --port 8000
```

School frontend:

```bash
cd frontend
npm install
npm start
```

Super admin dashboard:

```bash
cd super-admin-dashboard
npm install
npm run dev
```

## Recommended Beta Deployment Structure

- Backend API: Render, Railway, Fly.io, or a VPS running FastAPI with HTTPS.
- School frontend: Vercel, Netlify, Cloudflare Pages, or static hosting.
- Super admin dashboard: Vercel, Netlify, Cloudflare Pages, or a separate private/static site.
- Database: MongoDB Atlas with IP allowlisting and separate beta database.
- Uploads: For beta, local backend uploads can work on persistent-disk hosting. For multi-instance or production, move uploads to S3, Cloudflare R2, or another managed object store.

Use separate public domains, for example:

- `https://api.smartmhub.example`
- `https://school.smartmhub.example`
- `https://admin.smartmhub.example`

## Deployment Steps

1. Create a MongoDB Atlas cluster and database, for example `smart_m_hub_beta`.
2. Create a strong `SECRET_KEY`.
3. Deploy the backend with the backend environment variables above.
4. Set backend CORS with `ALLOWED_ORIGINS=https://school-domain,https://admin-domain`.
5. Deploy the school frontend with `REACT_APP_BACKEND_URL=https://api-domain`.
6. Deploy the super admin dashboard with `VITE_API_BASE_URL=https://api-domain/api/platform`.
7. Seed or create one platform owner/super admin account securely.
8. Visit `/docs` on the backend API domain to confirm the API is reachable.
9. Register a test school from the school frontend.
10. Approve that school from the super admin dashboard.
11. Test each role from different browsers/devices.

## Cloudflare Tunnel Beta Testing

If testers access the school frontend through a Cloudflare tunnel, the browser is running on the tester's device. Do not let the frontend call `http://127.0.0.1:8000`, because that points to the tester's own device, not your backend.

Use two public URLs:

- One tunnel/domain for the backend API.
- One tunnel/domain for the school frontend.

Backend environment:

```env
FRONTEND_URL=https://your-school-frontend.trycloudflare.com
ALLOWED_ORIGINS=https://your-school-frontend.trycloudflare.com
ALLOW_CLOUDFLARE_TUNNEL=true
```

School frontend environment before starting/building:

```env
REACT_APP_BACKEND_URL=https://your-backend-api.trycloudflare.com
```

Then restart the frontend process so React picks up the environment variable.

## Beta Safety Checklist

- `APP_ENV=production` is set on the backend.
- `SECRET_KEY` is set and not committed.
- `MONGO_URL` is the Atlas connection URI with `authSource=admin`; `DB_NAME` selects the beta database used by the application.
- `ALLOWED_ORIGINS` includes only deployed frontend domains.
- Frontend env variables point to the deployed backend URL.
- Demo/test credentials are not committed.
- New schools remain pending until approved by the platform owner.
- Users who join a school remain pending until approved by the school admin.
- Student/parent portal data is limited to the linked student account.
- Backups are enabled for the beta database.

## Verification Commands

Backend:

```bash
python -m pytest backend -p no:cacheprovider
```

School frontend:

```bash
cd frontend
npm test -- --watchAll=false --runInBand --passWithNoTests
```

Super admin dashboard:

```bash
cd super-admin-dashboard
npm run build
```

Run frontend build checks before deploying public beta builds.
