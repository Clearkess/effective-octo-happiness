from __future__ import annotations

import os
import secrets
import sqlite3
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
UPLOAD_ROOT = Path(os.getenv("UPLOAD_ROOT", str(DEFAULT_UPLOAD_ROOT)))
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "14"))
PORT = int(os.getenv("PORT") or "8000")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "16"))
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

DEFAULT_HOLDINGS = [
    {"symbol": "BTC", "name": "Bitcoin", "pct": 42, "color": "#46a0ff", "price": 104821, "change": 2.1},
    {"symbol": "ETH", "name": "Ethereum", "pct": 28, "color": "#7c4dff", "price": 5148, "change": 1.4},
    {"symbol": "SOL", "name": "Solana", "pct": 16, "color": "#36d399", "price": 311, "change": -0.5},
    {"symbol": "USDC", "name": "USDC", "pct": 14, "color": "#ffd36f", "price": 1, "change": 0},
]

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
        reviewed_at TEXT
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
        return pg_connect(DATABASE_URL, row_factory=dict_row)
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
    commit(conn)

    admin = query_one("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,), conn=conn)
    if not admin:
        execute(
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
        )
        commit(conn)
        admin = query_one("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,), conn=conn)

    ensure_user_bootstrap(admin["id"], conn=conn)
    commit(conn)
    conn.close()


_db_initialized = False


def ensure_database_initialized() -> None:
    global _db_initialized
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
        execute(
            "INSERT INTO settings (user_id, risk_profile, email_alerts, product_updates, two_factor) VALUES (?, ?, ?, ?, ?)",
            (user_id, "Balanced", True, True, False),
            conn=target,
        )

    if not query_one("SELECT user_id FROM kyc WHERE user_id = ?", (user_id,), conn=target):
        execute(
            "INSERT INTO kyc (user_id, current_step, submitted, status) VALUES (?, ?, ?, ?)",
            (user_id, 0, False, "draft"),
            conn=target,
        )

    if not query_one("SELECT user_id FROM wallets WHERE user_id = ?", (user_id,), conn=target):
        execute(
            "INSERT INTO wallets (user_id, address, updated_at) VALUES (?, ?, ?)",
            (user_id, None, iso_now()),
            conn=target,
        )

    if not query_one("SELECT id FROM deposit_addresses WHERE user_id = ? LIMIT 1", (user_id,), conn=target):
        executemany(
            "INSERT INTO deposit_addresses (user_id, asset, network, address) VALUES (?, ?, ?, ?)",
            [
                (user_id, "BTC", "BTC", f"bc1qblockharbor{int(user_id):04d}btc89f2"),
                (user_id, "USDT", "ERC-20", f"0xB10cHarbor{int(user_id):04d}00000000000000000000"),
            ],
            conn=target,
        )

    if not query_one("SELECT id FROM transactions WHERE user_id = ? LIMIT 1", (user_id,), conn=target):
        executemany(
            "INSERT INTO transactions (user_id, type, asset, amount, value_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (user_id, "Buy", "BTC", "0.1800 BTC", "$18,912", "Completed", iso_now()),
                (user_id, "Deposit", "USDT", "4,500 USDT", "$4,500", "Pending", iso_now()),
                (user_id, "KYC", "Address proof", "Document upload", "Verification", "In review", iso_now()),
                (user_id, "Buy", "ETH", "2.3000 ETH", "$11,840", "Completed", iso_now()),
            ],
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


def fetch_kyc_file(file_id: int):
    return query_one("SELECT * FROM kyc_files WHERE id = ?", (file_id,))


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
        
