from __future__ import annotations

import hashlib
import io
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Iterable

from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = BASE_DIR
DEFAULT_SQLITE_PATH = BACKEND_DIR / "blockharbor.db"
DEFAULT_UPLOAD_ROOT = BACKEND_DIR / "uploads" / "kyc"

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_BACKEND = "postgres" if DATABASE_URL.startswith(("postgres://", "postgresql://")) else "sqlite"
SQLITE_PATH = Path(os.getenv("SQLITE_PATH", str(DEFAULT_SQLITE_PATH)))

# Vercel's deployment filesystem is read-only except for /tmp.
# KYC uploads are intentionally blocked on Vercel unless object storage is configured.
DEFAULT_VERCEL_UPLOAD_ROOT = Path("/tmp/blockharbor/kyc")
DEFAULT_UPLOAD_PATH = DEFAULT_VERCEL_UPLOAD_ROOT if os.getenv("VERCEL") == "1" else DEFAULT_UPLOAD_ROOT
UPLOAD_ROOT = Path(os.getenv("UPLOAD_ROOT", str(DEFAULT_UPLOAD_PATH)))


def kyc_storage_backend() -> str:
    """Return "db" or "filesystem" for KYC document storage.

    On Vercel the deployment filesystem is read-only apart from /tmp, and
    /tmp is per-instance and discarded on cold start, so a document written
    there can silently disappear. "auto" therefore keeps documents in the
    database there. Set KYC_STORAGE=filesystem or KYC_STORAGE=db to force it.
    """
    if KYC_STORAGE in ("db", "filesystem"):
        return KYC_STORAGE
    return "db" if VERCEL_RUNTIME else "filesystem"
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "14"))
PORT = int(os.getenv("PORT") or "8000")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "16"))
# Vercel sets VERCEL=1 in the build and in the function runtime.
VERCEL_RUNTIME = os.getenv("VERCEL") == "1"
# Where KYC documents live. "auto" = database on Vercel (its filesystem is
# read-only and wiped between cold starts), disk everywhere else.
KYC_STORAGE = os.getenv("KYC_STORAGE", "auto").strip().lower()
# Vercel rejects request bodies over ~4.5 MB before our code ever runs.
MAX_KYC_DB_MB = int(os.getenv("MAX_KYC_DB_MB", "4"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@blockharbor.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
APP_ENV = os.getenv("APP_ENV", "development")


if APP_ENV == "production" and not DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be set in production")
if APP_ENV == "production" and not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD must be set in production")

if DB_BACKEND == "postgres":
    from psycopg import connect as pg_connect
    from psycopg.rows import dict_row

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False

# No starting positions are written. A new account begins empty; real positions
# are entered through PUT /api/admin/users/<id>/portfolio.


# The HTML pages reference /assets/css/styles.css and /assets/js/app.js, but the
# files live at the repo root (styles.css, app.js). Alias the asset paths so the
# catch-all frontend route serves them instead of aborting with 404.
ASSET_ALIASES = {
    "assets/css/styles.css": "styles.css",
    "assets/js/app.js": "app.js",
}

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    country TEXT,
    phone TEXT,
    created_at TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER PRIMARY KEY,
    risk_profile TEXT NOT NULL DEFAULT 'Balanced',
    email_alerts INTEGER NOT NULL DEFAULT 1,
    product_updates INTEGER NOT NULL DEFAULT 1,
    two_factor INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS kyc (
    user_id INTEGER PRIMARY KEY,
    current_step INTEGER NOT NULL DEFAULT 0,
    submitted INTEGER NOT NULL DEFAULT 0,
    submitted_at TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    reviewer_note TEXT,
    reviewed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS wallets (
    user_id INTEGER PRIMARY KEY,
    address TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS deposit_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    asset TEXT NOT NULL,
    network TEXT NOT NULL,
    address TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    asset TEXT NOT NULL,
    amount TEXT NOT NULL,
    value_text TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS kyc_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    step_key TEXT NOT NULL,
    document_type TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'uploaded',
    reviewer_note TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    storage_backend TEXT NOT NULL DEFAULT 'filesystem',
    content_sha256 TEXT,
    file_data BLOB,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS portfolio (
    user_id INTEGER PRIMARY KEY,
    cash_balance REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS holdings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    quantity REAL NOT NULL DEFAULT 0,
    price REAL NOT NULL DEFAULT 0,
    change_24h REAL NOT NULL DEFAULT 0,
    color TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

POSTGRES_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        country TEXT,
        phone TEXT,
        created_at TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id),
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS settings (
        user_id BIGINT PRIMARY KEY REFERENCES users(id),
        risk_profile TEXT NOT NULL DEFAULT 'Balanced',
        email_alerts BOOLEAN NOT NULL DEFAULT TRUE,
        product_updates BOOLEAN NOT NULL DEFAULT TRUE,
        two_factor BOOLEAN NOT NULL DEFAULT FALSE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kyc (
        user_id BIGINT PRIMARY KEY REFERENCES users(id),
        current_step INTEGER NOT NULL DEFAULT 0,
        submitted BOOLEAN NOT NULL DEFAULT FALSE,
        submitted_at TEXT,
        status TEXT NOT NULL DEFAULT 'draft',
        reviewer_note TEXT,
        reviewed_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS wallets (
        user_id BIGINT PRIMARY KEY REFERENCES users(id),
        address TEXT,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS deposit_addresses (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id),
        asset TEXT NOT NULL,
        network TEXT NOT NULL,
        address TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transactions (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id),
        type TEXT NOT NULL,
        asset TEXT NOT NULL,
        amount TEXT NOT NULL,
        value_text TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kyc_files (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id),
        step_key TEXT NOT NULL,
        document_type TEXT NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        mime_type TEXT,
        size_bytes BIGINT NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'uploaded',
        reviewer_note TEXT,
        created_at TEXT NOT NULL,
        reviewed_at TEXT,
        storage_backend TEXT NOT NULL DEFAULT 'filesystem',
        content_sha256 TEXT,
        file_data BYTEA
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS portfolio (
        user_id BIGINT PRIMARY KEY REFERENCES users(id),
        cash_balance DOUBLE PRECISION NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS holdings (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id),
        symbol TEXT NOT NULL,
        name TEXT NOT NULL,
        quantity DOUBLE PRECISION NOT NULL DEFAULT 0,
        price DOUBLE PRECISION NOT NULL DEFAULT 0,
        change_24h DOUBLE PRECISION NOT NULL DEFAULT 0,
        color TEXT,
        updated_at TEXT NOT NULL
    )
    """,
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def adapt_sql(sql: str) -> str:
    return sql.replace("?", "%s") if DB_BACKEND == "postgres" else sql


def connect_db():
    if DB_BACKEND == "postgres":
        # Neon connection strings normally already contain sslmode=require.
        # Add it defensively when a manually-created URL omits it.
        url = DATABASE_URL
        if "sslmode=" not in url:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}sslmode=require"
        return pg_connect(url, row_factory=dict_row, connect_timeout=10)

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def execute(sql: str, params: Iterable[Any] = (), conn=None):
    target = conn or get_db()
    cur = target.cursor()
    cur.execute(adapt_sql(sql), tuple(params))
    return cur


def executemany(sql: str, param_rows: Iterable[Iterable[Any]], conn=None):
    target = conn or get_db()
    cur = target.cursor()
    cur.executemany(adapt_sql(sql), [tuple(row) for row in param_rows])
    return cur


def query_one(sql: str, params: Iterable[Any] = (), conn=None):
    return execute(sql, params, conn=conn).fetchone()


def query_all(sql: str, params: Iterable[Any] = (), conn=None):
    return execute(sql, params, conn=conn).fetchall()


def commit(conn=None) -> None:
    (conn or get_db()).commit()


def safe_execute(sql: str, params: Iterable[Any] = (), conn=None) -> bool:
    """Run a statement that may collide with a concurrent cold start.

    Two serverless instances can boot at the same moment and both try to
    create the admin user / bootstrap rows. The loser gets a duplicate-key
    error, which aborts the surrounding transaction, so undo it and let the
    caller re-read the row that the winner inserted.
    """
    target = conn or get_db()
    try:
        execute(sql, params, conn=target)
        return True
    except Exception:
        try:
            target.rollback()
        except Exception:
            pass
        return False


def row_get(row, key, default=None):
    """Read a column portably: sqlite3.Row raises IndexError, dicts KeyError."""
    try:
        value = row[key]
    except (KeyError, IndexError):
        return default
    return default if value is None else value


# Explicit column list for KYC metadata. Deliberately excludes file_data: a bare
# SELECT * would drag every stored document over the wire on list requests.
KYC_FILE_COLUMNS = (
    "id, user_id, step_key, document_type, original_name, stored_name, file_path, "
    "mime_type, size_bytes, status, reviewer_note, created_at, reviewed_at, "
    "storage_backend, content_sha256"
)


def ensure_column(conn, table: str, column_name: str, definition: str) -> None:
    if DB_BACKEND == "sqlite":
        existing = {row["name"] for row in query_all(f"PRAGMA table_info({table})", conn=conn)}
        if column_name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
        return

    existing = {
        row["column_name"]
        for row in query_all(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ?",
            (table,),
            conn=conn,
        )
    }
    if column_name not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def init_db() -> None:
    if APP_ENV == "production" and DB_BACKEND != "postgres":
        raise RuntimeError("Production deployments require PostgreSQL via DATABASE_URL")
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    conn = connect_db()
    if DB_BACKEND == "sqlite":
        conn.executescript(SQLITE_SCHEMA)
    else:
        for statement in POSTGRES_SCHEMA:
            conn.execute(statement)

    ensure_column(conn, "users", "role", "role TEXT NOT NULL DEFAULT 'user'")
    ensure_column(conn, "kyc", "status", "status TEXT NOT NULL DEFAULT 'draft'")
    ensure_column(conn, "kyc", "reviewer_note", "reviewer_note TEXT")
    ensure_column(conn, "kyc", "reviewed_at", "reviewed_at TEXT")
    ensure_column(conn, "kyc_files", "storage_backend", "storage_backend TEXT NOT NULL DEFAULT 'filesystem'")
    ensure_column(conn, "kyc_files", "content_sha256", "content_sha256 TEXT")
    ensure_column(conn, "kyc_files", "file_data", f"file_data {'BYTEA' if DB_BACKEND == 'postgres' else 'BLOB'}")
    commit(conn)

    admin = query_one("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,), conn=conn)
    if not admin:
        # Another instance may have created it between the check and the insert.
        if safe_execute(
            "INSERT INTO users (first_name, last_name, email, password_hash, country, phone, created_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "Admin",
                "User",
                ADMIN_EMAIL,
                generate_password_hash(ADMIN_PASSWORD),
                "Internal",
                "",
                iso_now(),
                "admin",
            ),
            conn=conn,
        ):
            commit(conn)
        admin = query_one("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,), conn=conn)

    if not admin:
        raise RuntimeError("Could not create or read the bootstrap admin user")

    ensure_user_bootstrap(admin["id"], conn=conn)
    commit(conn)
    conn.close()


_db_initialized = False


_init_lock = threading.Lock()


def ensure_database_initialized() -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _init_lock:
        if _db_initialized:
            return
        init_db()
        _db_initialized = True


@app.before_request
def initialize_database_for_request():
    ensure_database_initialized()


def create_session(user_id: int) -> str:
    token = secrets.token_hex(24)
    execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token, user_id, (utc_now() + timedelta(days=SESSION_DAYS)).isoformat(), iso_now()),
    )
    commit()
    return token


def get_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def get_user_from_token(token: str | None):
    if not token:
        return None
    return query_one(
        """
        SELECT users.*
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ? AND sessions.expires_at > ?
        """,
        (token, iso_now()),
    )


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        user = get_user_from_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        g.current_user = user
        g.current_token = token
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    @auth_required
    def wrapper(*args, **kwargs):
        if g.current_user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)

    return wrapper


def serialize_user(user) -> dict[str, Any]:
    return {
        "id": user["id"],
        "firstName": user["first_name"],
        "lastName": user["last_name"],
        "email": user["email"],
        "country": user["country"],
        "phone": user["phone"],
        "createdAt": user["created_at"],
        "role": user["role"],
    }


def serialize_kyc_file(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "userId": row["user_id"],
        "stepKey": row["step_key"],
        "documentType": row["document_type"],
        "originalName": row["original_name"],
        "mimeType": row["mime_type"],
        "sizeBytes": row["size_bytes"],
        "status": row["status"],
        "reviewerNote": row["reviewer_note"],
        "createdAt": row["created_at"],
        "reviewedAt": row["reviewed_at"],
        "storageBackend": row_get(row, "storage_backend", "filesystem"),
        "checksum": row_get(row, "content_sha256"),
    }


def record_transaction(user_id: int, tx_type: str, asset: str, amount: str, value_text: str, status: str) -> None:
    execute(
        "INSERT INTO transactions (user_id, type, asset, amount, value_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, tx_type, asset, amount, value_text, status, iso_now()),
    )
    commit()


def ensure_user_bootstrap(user_id: int, conn=None) -> None:
    target = conn or get_db()

    if not query_one("SELECT user_id FROM settings WHERE user_id = ?", (user_id,), conn=target):
        safe_execute(
            "INSERT INTO settings (user_id, risk_profile, email_alerts, product_updates, two_factor) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Balanced", True, True, False),
            conn=target,
        )

    if not query_one("SELECT user_id FROM kyc WHERE user_id = ?", (user_id,), conn=target):
        safe_execute(
            "INSERT INTO kyc (user_id, current_step, submitted, status) VALUES (?, ?, ?, ?)",
            (user_id, 0, False, "draft"),
            conn=target,
        )

    if not query_one("SELECT user_id FROM wallets WHERE user_id = ?", (user_id,), conn=target):
        safe_execute(
            "INSERT INTO wallets (user_id, address, updated_at) VALUES (?, ?, ?)",
            (user_id, None, iso_now()),
            conn=target,
        )


    if not query_one("SELECT user_id FROM portfolio WHERE user_id = ?", (user_id,), conn=target):
        safe_execute(
            "INSERT INTO portfolio (user_id, cash_balance, updated_at) VALUES (?, ?, ?)",
            (user_id, 0.0, iso_now()),
            conn=target,
        )



    commit(target)


def sync_kyc_status(user_id: int) -> None:
    stats = query_one(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected
        FROM kyc_files
        WHERE user_id = ?
        """,
        (user_id,),
    )
    kyc = query_one("SELECT submitted FROM kyc WHERE user_id = ?", (user_id,))

    total = stats["total"] or 0
    approved = stats["approved"] or 0
    rejected = stats["rejected"] or 0
    submitted = bool(kyc["submitted"]) if kyc else False

    status = "draft"
    if total > 0:
        status = "uploaded"
    if submitted:
        status = "submitted"
    if rejected > 0:
        status = "needs_attention"
    elif submitted and total > 0 and approved == total:
        status = "approved"

    execute("UPDATE kyc SET status = ? WHERE user_id = ?", (status, user_id))
    commit()


def allocate_percentages(values: list[float], total: int = 100) -> list[int]:
    """Split `total` across `values` so the parts sum to exactly `total`.

    Rounding each share independently drifts (four assets can total 101%), so the
    remainders are distributed to the largest fractional parts first.
    """
    if not values or sum(values) <= 0:
        return [0] * len(values)
    scale = total / sum(values)
    raw = [v * scale for v in values]
    parts = [int(r) for r in raw]
    leftover = total - sum(parts)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - parts[i], reverse=True)
    for i in order[:leftover]:
        parts[i] += 1
    return parts


def load_portfolio(user_id: int) -> dict[str, Any]:
    """Portfolio figures computed from the database, not from source code.

    totalBalance = sum(quantity x price) + cash, and each holding's allocation
    percentage is derived from those values rather than stored by hand.
    """
    account = query_one("SELECT cash_balance FROM portfolio WHERE user_id = ?", (user_id,))
    rows = query_all(
        "SELECT symbol, name, quantity, price, change_24h, color FROM holdings WHERE user_id = ? ORDER BY id ASC",
        (user_id,),
    )
    cash = float(account["cash_balance"]) if account else 0.0

    holdings = []
    invested = 0.0
    for row in rows:
        value = float(row["quantity"]) * float(row["price"])
        invested += value
        holdings.append(
            {
                "symbol": row["symbol"],
                "name": row["name"],
                "quantity": float(row["quantity"]),
                "price": float(row["price"]),
                "change": float(row["change_24h"]),
                "color": row["color"] or "#46a0ff",
                "value": round(value, 2),
            }
        )
    for item, pct in zip(holdings, allocate_percentages([h["value"] for h in holdings])):
        item["pct"] = pct

    return {
        "totalBalance": round(invested + cash, 2),
        "availableCash": round(cash, 2),
        "investedValue": round(invested, 2),
        "holdings": holdings,
    }


def fetch_kyc_file(file_id: int):
    return query_one(f"SELECT {KYC_FILE_COLUMNS} FROM kyc_files WHERE id = ?", (file_id,))


def fetch_kyc_blob(file_id: int):
    row = query_one("SELECT file_data FROM kyc_files WHERE id = ?", (file_id,))
    return row["file_data"] if row else None


@app.get("/api/health")
def health():
    db_ok = False
    try:
        query_one("SELECT 1 AS ok")
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({"ok": True, "environment": APP_ENV, "backend": DB_BACKEND, "database": db_ok, "timestamp": iso_now()})


@app.post("/api/auth/signup")
def signup():
    payload = request.get_json(silent=True) or {}
    first = (payload.get("firstName") or "").strip()
    last = (payload.get("lastName") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    country = (payload.get("country") or "").strip()
    phone = (payload.get("phone") or "").strip()

    if not all([first, last, email, password]):
        return jsonify({"error": "Missing required signup fields"}), 400

    if query_one("SELECT id FROM users WHERE email = ?", (email,)):
        return jsonify({"error": "An account with this email already exists"}), 409

    execute(
        "INSERT INTO users (first_name, last_name, email, password_hash, country, phone, created_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (first, last, email, generate_password_hash(password), country, phone, iso_now(), "user"),
    )
    commit()
    user = query_one("SELECT * FROM users WHERE email = ?", (email,))
    ensure_user_bootstrap(user["id"])
    record_transaction(user["id"], "Signup", "Account", "New account", "Onboarding started", "Completed")
    token = create_session(user["id"])
    return jsonify({"token": token, "user": serialize_user(user)})


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    user = query_one("SELECT * FROM users WHERE email = ?", (email,))
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401
    ensure_user_bootstrap(user["id"])
    token = create_session(user["id"])
    return jsonify({"token": token, "user": serialize_user(user)})


@app.post("/api/auth/logout")
@auth_required
def logout():
    execute("DELETE FROM sessions WHERE token = ?", (g.current_token,))
    commit()
    return jsonify({"ok": True})


@app.get("/api/auth/me")
@auth_required
def me():
    return jsonify({"user": serialize_user(g.current_user)})


@app.get("/api/dashboard/overview")
@auth_required
def dashboard_overview():
    user_id = g.current_user["id"]
    ensure_user_bootstrap(user_id)
    wallet = query_one("SELECT address FROM wallets WHERE user_id = ?", (user_id,))
    kyc = query_one("SELECT current_step, submitted, status, reviewer_note FROM kyc WHERE user_id = ?", (user_id,))
    tx_rows = query_all(
        "SELECT type, asset, amount, value_text, status, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (user_id,),
    )
    return jsonify(
        {
            "user": serialize_user(g.current_user),
            "portfolio": {
                **load_portfolio(user_id),
                "wallet": wallet["address"] if wallet else None,
                "kycSubmitted": bool(kyc["submitted"]) if kyc else False,
                "kycStep": int(kyc["current_step"]) if kyc else 0,
                "kycStatus": kyc["status"] if kyc else "draft",
                "kycReviewerNote": kyc["reviewer_note"] if kyc else None,
            },
            "activity": [
                {"label": f"{row['type']}: {row['asset']} — {row['status']}", "time": row["created_at"]}
                for row in tx_rows
            ],
        }
    )


@app.get("/api/transactions")
@auth_required
def transactions():
    rows = query_all(
        "SELECT type, asset, amount, value_text, status, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC",
        (g.current_user["id"],),
    )
    return jsonify(
        {
            "transactions": [
                {
                    "type": row["type"],
                    "asset": row["asset"],
                    "amount": row["amount"],
                    "value": row["value_text"],
                    "status": row["status"],
                    "when": row["created_at"],
                }
                for row in rows
            ]
        }
    )


@app.get("/api/deposit-addresses")
@auth_required
def deposit_addresses():
    rows = query_all(
        "SELECT asset, network, address FROM deposit_addresses WHERE user_id = ? ORDER BY id ASC",
        (g.current_user["id"],),
    )
    return jsonify({"addresses": [dict(row) for row in rows]})


@app.post("/api/withdrawals")
@auth_required
def create_withdrawal():
    payload = request.get_json(silent=True) or {}
    asset = (payload.get("asset") or "USDT").strip() or "USDT"
    network = (payload.get("network") or "ERC-20").strip() or "ERC-20"
    amount = (payload.get("amount") or "").strip()
    address = (payload.get("address") or "").strip()
    if not amount or not address:
        return jsonify({"error": "Amount and destination address are required"}), 400
    record_transaction(g.current_user["id"], "Withdraw", asset, f"{amount} {asset}", f"To {network}", "Pending")
    return jsonify({"ok": True})


@app.get("/api/settings")
@auth_required
def get_settings():
    row = query_one(
        "SELECT risk_profile, email_alerts, product_updates, two_factor FROM settings WHERE user_id = ?",
        (g.current_user["id"],),
    )
    return jsonify(
        {
            "settings": {
                "riskProfile": row["risk_profile"],
                "emailAlerts": bool(row["email_alerts"]),
                "productUpdates": bool(row["product_updates"]),
                "twoFactor": bool(row["two_factor"]),
            }
        }
    )


@app.put("/api/settings")
@auth_required
def update_settings():
    payload = request.get_json(silent=True) or {}
    execute(
        "UPDATE settings SET risk_profile = ?, email_alerts = ?, product_updates = ?, two_factor = ? WHERE user_id = ?",
        (
            payload.get("riskProfile") or "Balanced",
            bool(payload.get("emailAlerts")),
            bool(payload.get("productUpdates")),
            bool(payload.get("twoFactor")),
            g.current_user["id"],
        ),
    )
    commit()
    return jsonify({"ok": True})


@app.get("/api/kyc")
@auth_required
def get_kyc():
    row = query_one(
        "SELECT current_step, submitted, submitted_at, status, reviewer_note, reviewed_at FROM kyc WHERE user_id = ?",
        (g.current_user["id"],),
    )
    return jsonify(
        {
            "kyc": {
                "currentStep": int(row["current_step"]),
                "submitted": bool(row["submitted"]),
                "submittedAt": row["submitted_at"],
                "status": row["status"],
                "reviewerNote": row["reviewer_note"],
                "reviewedAt": row["reviewed_at"],
            }
        }
    )


@app.put("/api/kyc/draft")
@auth_required
def update_kyc_draft():
    current_step = max(0, min(int((request.get_json(silent=True) or {}).get("currentStep", 0)), 4))
    execute("UPDATE kyc SET current_step = ? WHERE user_id = ?", (current_step, g.current_user["id"]))
    commit()
    return jsonify({"ok": True})


@app.post("/api/kyc/submit")
@auth_required
def submit_kyc():
    execute(
        "UPDATE kyc SET current_step = 4, submitted = ?, submitted_at = ?, status = 'submitted' WHERE user_id = ?",
        (True, iso_now(), g.current_user["id"]),
    )
    commit()
    record_transaction(g.current_user["id"], "KYC", "Verification package", "5 checklist items", "Submitted", "In review")
    sync_kyc_status(g.current_user["id"])
    return jsonify({"ok": True})


@app.get("/api/kyc/files")
@auth_required
def list_kyc_files():
    rows = query_all("SELECT * FROM kyc_files WHERE user_id = ? ORDER BY id DESC", (g.current_user["id"],))
    return jsonify({"files": [serialize_kyc_file(row) for row in rows]})


@app.post("/api/kyc/files")
@auth_required
def upload_kyc_file():
    upload = request.files.get("file")
    step_key = (request.form.get("stepKey") or "general").strip()
    document_type = (request.form.get("documentType") or step_key).strip()
    if not upload or not upload.filename:
        return jsonify({"error": "No file selected"}), 400

    safe_name = secure_filename(upload.filename)
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    backend = kyc_storage_backend()
    if backend == "filesystem" and VERCEL_RUNTIME:
        return (
            jsonify(
                {
                    "error": "KYC_STORAGE=filesystem cannot be used on Vercel: the filesystem is "
                    "read-only apart from /tmp, which is discarded on cold start. Use KYC_STORAGE=db."
                }
            ),
            503,
        )

    payload = upload.read()
    size_bytes = len(payload)
    if size_bytes == 0:
        return jsonify({"error": "The selected file is empty"}), 400
    if size_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        return jsonify({"error": f"File is larger than the {MAX_UPLOAD_MB} MB limit"}), 413
    if backend == "db" and size_bytes > MAX_KYC_DB_MB * 1024 * 1024:
        return (
            jsonify(
                {
                    "error": f"Files up to {MAX_KYC_DB_MB} MB are accepted while documents are stored in "
                    "the database. Raise MAX_KYC_DB_MB, or configure KYC_STORAGE=filesystem with a "
                    "persistent volume."
                }
            ),
            413,
        )

    user_id = g.current_user["id"]
    created_at = iso_now()
    stored_name = f"{secrets.token_hex(8)}_{safe_name}"
    digest = hashlib.sha256(payload).hexdigest()

    if backend == "db":
        file_path = "pending"
    else:
        user_dir = UPLOAD_ROOT / str(user_id)
        user_dir.mkdir(parents=True, exist_ok=True)
        target = user_dir / stored_name
        target.write_bytes(payload)
        file_path = str(target)

    insert_sql = (
        "INSERT INTO kyc_files (user_id, step_key, document_type, original_name, stored_name, file_path, "
        "mime_type, size_bytes, status, created_at, storage_backend, content_sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'uploaded', ?, ?, ?)"
    )
    insert_params = (
        user_id,
        step_key,
        document_type,
        upload.filename,
        stored_name,
        file_path,
        upload.mimetype,
        size_bytes,
        created_at,
        backend,
        digest,
    )
    if DB_BACKEND == "postgres":
        new_id = execute(insert_sql + " RETURNING id", insert_params).fetchone()["id"]
    else:
        new_id = execute(insert_sql, insert_params).lastrowid

    if backend == "db":
        execute("UPDATE kyc_files SET file_data = ?, file_path = ? WHERE id = ?", (payload, f"db://kyc_files/{new_id}", new_id))
    execute("UPDATE kyc SET status = 'uploaded' WHERE user_id = ? AND status = 'draft'", (user_id,))
    commit()
    record_transaction(user_id, "KYC Upload", document_type, upload.filename, "Document received", "Uploaded")
    sync_kyc_status(user_id)
    newest = query_one(f"SELECT {KYC_FILE_COLUMNS} FROM kyc_files WHERE id = ?", (new_id,))
    return jsonify({"file": serialize_kyc_file(newest)})


@app.get("/api/kyc/files/<int:file_id>/download")
@auth_required
def download_kyc_file(file_id: int):
    row = fetch_kyc_file(file_id)
    if not row:
        abort(404)
    if g.current_user["role"] != "admin" and row["user_id"] != g.current_user["id"]:
        return jsonify({"error": "Forbidden"}), 403

    if row_get(row, "storage_backend", "filesystem") == "db":
        blob = fetch_kyc_blob(file_id)
        if blob is None:
            return jsonify({"error": "Stored document is missing"}), 404
        return send_file(
            io.BytesIO(bytes(blob)),
            as_attachment=True,
            download_name=row["original_name"],
            mimetype=row["mime_type"] or "application/octet-stream",
        )

    path = Path(row["file_path"])
    if not path.exists():
        return jsonify({"error": "Stored document is missing from disk"}), 404
    return send_file(path, as_attachment=True, download_name=row["original_name"])


@app.post("/api/profile/wallet")
@auth_required
def save_wallet():
    address = ((request.get_json(silent=True) or {}).get("address") or "").strip()
    if not address:
        return jsonify({"error": "Wallet address is required"}), 400
    execute("UPDATE wallets SET address = ?, updated_at = ? WHERE user_id = ?", (address, iso_now(), g.current_user["id"]))
    commit()
    return jsonify({"ok": True})


@app.get("/api/admin/overview")
@admin_required
def admin_overview():
    stats = {
        "users": query_one("SELECT COUNT(*) AS c FROM users")["c"],
        "pendingFiles": query_one("SELECT COUNT(*) AS c FROM kyc_files WHERE status = 'uploaded'")["c"],
        "submittedKyc": query_one("SELECT COUNT(*) AS c FROM kyc WHERE submitted = TRUE")["c"],
        "transactions": query_one("SELECT COUNT(*) AS c FROM transactions")["c"],
    }
    recent_users = query_all("SELECT id, first_name, last_name, email, role, created_at FROM users ORDER BY id DESC LIMIT 6")
    pending_files = query_all(
        """
        SELECT kyc_files.id, kyc_files.document_type, kyc_files.status, kyc_files.created_at,
               users.first_name, users.last_name, users.email
        FROM kyc_files
        JOIN users ON users.id = kyc_files.user_id
        WHERE kyc_files.status = 'uploaded'
        ORDER BY kyc_files.id DESC
        LIMIT 10
        """
    )
    return jsonify({"stats": stats, "recentUsers": [dict(row) for row in recent_users], "pendingFiles": [dict(row) for row in pending_files]})


@app.put("/api/admin/users/<int:user_id>/portfolio")
@admin_required
def admin_update_portfolio(user_id: int):
    """Set a user's cash balance and holdings.

    Send {"cashBalance": 0, "holdings": [{"symbol": "BTC",
    """
    if not query_one("SELECT id FROM users WHERE id = ?", (user_id,)):
        return jsonify({"error": "Unknown user"}), 404
    if not query_one("SELECT user_id FROM portfolio WHERE user_id = ?", (user_id,)):
        return jsonify({"error": "This user has no portfolio row yet"}), 404

    payload = request.get_json(silent=True) or {}

    if "cashBalance" in payload:
        try:
            cash = float(payload["cashBalance"])
        except (TypeError, ValueError):
            return jsonify({"error": "cashBalance must be a number"}), 400
        execute("UPDATE portfolio SET cash_balance = ?, updated_at = ? WHERE user_id = ?", (cash, iso_now(), user_id))


    holdings = payload.get("holdings")
    if holdings is not None and not isinstance(holdings, list):
        return jsonify({"error": "holdings must be a list"}), 400
    for item in holdings or []:
        if not isinstance(item, dict):
            return jsonify({"error": "each holding must be an object"}), 400
        symbol = str(item.get("symbol") or "").strip().upper()
        if not symbol:
            return jsonify({"error": "each holding needs a symbol"}), 400
        try:
            quantity = float(item.get("quantity"))
        except (TypeError, ValueError):
            return jsonify({"error": f"quantity for {symbol} must be a number"}), 400
        raw_price = item.get("price")
        price = None
        if raw_price is not None:
            try:
                price = float(raw_price)
            except (TypeError, ValueError):
                return jsonify({"error": f"price for {symbol} must be a number"}), 400

        existing = query_one("SELECT id FROM holdings WHERE user_id = ? AND symbol = ?", (user_id, symbol))
        if existing:
            if price is None:
                execute("UPDATE holdings SET quantity = ?, updated_at = ? WHERE id = ?", (quantity, iso_now(), existing["id"]))
            else:
                execute(
                    "UPDATE holdings SET quantity = ?, price = ?, updated_at = ? WHERE id = ?",
                    (quantity, price, iso_now(), existing["id"]),
                )
        elif price is not None:
            execute(
                "INSERT INTO holdings (user_id, symbol, name, quantity, price, change_24h, color, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, symbol, str(item.get("name") or symbol), quantity, price, 0, item.get("color"), iso_now()),
            )
        else:
            return jsonify({"error": f"{symbol} is a new holding and needs a price"}), 400

    commit()
    return jsonify({"portfolio": load_portfolio(user_id)})


@app.get("/api/admin/users")
@admin_required
def admin_users():
    rows = query_all(
        """
        SELECT users.id, users.first_name, users.last_name, users.email, users.role, users.created_at,
               COALESCE(kyc.status, 'draft') AS kyc_status,
               COALESCE(wallets.address, '') AS wallet_address
        FROM users
        LEFT JOIN kyc ON kyc.user_id = users.id
        LEFT JOIN wallets ON wallets.user_id = users.id
        ORDER BY users.id DESC
        """
    )
    return jsonify({"users": [dict(row) for row in rows]})


@app.get("/api/admin/kyc/files")
@admin_required
def admin_kyc_files():
    rows = query_all(
        """
        SELECT kyc_files.id, kyc_files.user_id, kyc_files.step_key, kyc_files.document_type,
               kyc_files.original_name, kyc_files.stored_name, kyc_files.file_path,
               kyc_files.mime_type, kyc_files.size_bytes, kyc_files.status,
               kyc_files.reviewer_note, kyc_files.created_at, kyc_files.reviewed_at,
               kyc_files.storage_backend, kyc_files.content_sha256,
               users.first_name, users.last_name, users.email
        FROM kyc_files
        JOIN users ON users.id = kyc_files.user_id
        ORDER BY kyc_files.id DESC
        """
    )
    files = []
    for row in rows:
        item = serialize_kyc_file(row)
        item["userName"] = f"{row['first_name']} {row['last_name']}"
        item["userEmail"] = row["email"]
        item["downloadUrl"] = f"/api/kyc/files/{row['id']}/download"
        files.append(item)
    return jsonify({"files": files})


@app.post("/api/admin/kyc/files/<int:file_id>/review")
@admin_required
def admin_review_kyc_file(file_id: int):
    payload = request.get_json(silent=True) or {}
    status = (payload.get("status") or "").strip().lower()
    note = (payload.get("reviewerNote") or "").strip()
    if status not in {"approved", "rejected"}:
        return jsonify({"error": "Review status must be approved or rejected"}), 400

    row = fetch_kyc_file(file_id)
    if not row:
        return jsonify({"error": "File not found"}), 404

    reviewed_at = iso_now()
    execute("UPDATE kyc_files SET status = ?, reviewer_note = ?, reviewed_at = ? WHERE id = ?", (status, note, reviewed_at, file_id))
    execute(
        "UPDATE kyc SET reviewer_note = ?, reviewed_at = ?, status = ? WHERE user_id = ?",
        (note, reviewed_at, "needs_attention" if status == "rejected" else "submitted", row["user_id"]),
    )
    commit()
    record_transaction(row["user_id"], "KYC Review", row["document_type"], row["original_name"], note or "Reviewed", status.title())
    sync_kyc_status(row["user_id"])
    return jsonify({"ok": True})


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def frontend(path: str):
    if path.startswith("api/"):
        abort(404)
    alias = ASSET_ALIASES.get(path)
    if alias and (BASE_DIR / alias).is_file():
        return send_from_directory(BASE_DIR, alias)
    candidate = BASE_DIR / path
    if candidate.is_file():
        return send_from_directory(BASE_DIR, path)
    if path in {"", "/"}:
        return send_from_directory(BASE_DIR, "index.html")
    if "." not in path:
        fallback = f"{path}.html"
        if (BASE_DIR / fallback).is_file():
            return send_from_directory(BASE_DIR, fallback)
    abort(404)


if __name__ == "__main__":
    ensure_database_initialized()
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
