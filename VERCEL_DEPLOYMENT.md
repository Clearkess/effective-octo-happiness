# Vercel deployment

This repository uses the Flask app in `app.py). Vercel can detect and run the Flask application without a custom `vercel.json`.

## Required Vercel environment variables

Set these for the Production environment:

- `APP_ENV=production`
- `DEBUG=false`
- `DATABASE_URL=<external PostgreSQL connection string>`
- `ADMIN_EMAIL=<your admin email>`
- `ADMIN_PASSWORD=<long random password>`
- `SESSION_DAYS=1`
- `MAX_UPLOAD_MB=16`

Do not commit real secrets.

## Database

Use a managed PostgreSQL database. Vercel's function filesystem is ephemeral, so SQLite is not suitable for production.

## KYC documents

KYC document uploads require persistent object storage. The repository intentionally returns a clear 503 response on Vercel until `KYC_OBJECT_STORAGE_URL` is configured. Do not rely on the Vercel function filesystem for permanent identity documents.

## Deploy

1. Import the GitHub repository into Vercel.
2. Select the `vercel-ready` branch for the first deployment.
3. Add the environment variables above.
4. Deploy.
5. Open `/api/health` and confirm the database reports healthy.
6. Test signup/login, dashboard, wallet linking, and the Sepolia-only demo flow.
7. Configure persistent KYC object storage before accepting document uploads.

The app remains non-custodial for crypto activity: wallet transactions are signed by the user's browser wallet and the application does not receive private keys or seed phrases.
