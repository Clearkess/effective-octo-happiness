# Railway deployment package for BlockHarbor / cryptosite

This package is prepared for a public Railway deployment using the existing root `Dockerfile`.

## What Railway will use
- Root `Dockerfile` for build and runtime
- `railway.json` for healthcheck and restart policy
- `/api/health` as the health endpoint

## Recommended Railway setup
1. Create a new Railway project.
2. Add a PostgreSQL service to the project.
3. Add this app as a service from your GitHub repo or by uploading the project.
4. Ensure the service root contains the `Dockerfile`.
5. In the app service variables, add the values from `.env.railway.example`.
6. Set `DATABASE_URL` in the app service by referencing the PostgreSQL service `DATABASE_URL` variable.
7. Add a persistent volume mounted at `/app/data` because KYC uploads are stored on disk.
8. In Public Networking, generate a Railway domain or attach your custom domain.
9. After deploy, verify `https://<your-domain>/api/health` returns HTTP 200.

## Important production notes
- Change `ADMIN_EMAIL` and `ADMIN_PASSWORD` before first public deploy.
- The app stores uploaded KYC files on the filesystem, so a persistent volume is strongly recommended.
- The current app is a demo/prototype and should be security-reviewed before handling real user funds or real KYC data.

## Expected app behavior
- Railway injects `PORT`; the app already binds to `PORT` through Gunicorn config.
- PostgreSQL should connect through `DATABASE_URL`.
- Healthcheck path is `/api/health`.

## Included fix
- Startup was adjusted so database initialization runs once before Gunicorn starts, avoiding multi-worker boot races during first deploy.
