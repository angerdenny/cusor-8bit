# -*- coding: utf-8 -*-
import os
from datetime import datetime, date, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# ========================
# Environment variables (.env must be next to main.py)
# ========================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name} (check .env)")
    return value


DATABASE_URL = require_env("DATABASE_URL")
JWT_SECRET = require_env("JWT_SECRET")
AGENT_API_KEY = require_env("AGENT_API_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

# ========================
# App
# ========================
app = FastAPI(title="AI Pulse Network Monitor", version="1.0.0")

# ========================
# Database
# ========================
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ========================
# Security
# ========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Failed login tracking per IP (in-memory, reset on server restart)
login_attempts = {}
MAX_ATTEMPTS = 10
BLOCK_DURATION = timedelta(hours=1)


# ========================
# Schemas
# ========================
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime | None = None


# ========================
# Helpers
# ========================
def row_to_dict(row) -> dict:
    """Convert a SQLAlchemy row to a JSON-safe dict (column-name agnostic)."""
    data = {}
    for key, value in row._mapping.items():
        if isinstance(value, (datetime, date)):
            value = value.isoformat()
        elif isinstance(value, Decimal):
            value = float(value)
        data[key] = value
    return data


def record_failure(ip: str):
    attempts, _ = login_attempts.get(ip, (0, None))
    login_attempts[ip] = (attempts + 1, datetime.now())


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


# JWT validation dependency (Header-based)
def get_current_user(authorization: str = Header(None)):
    """Verify JWT token and return current user info. Header: Authorization: Bearer <token>"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header format")

    try:
        payload = jwt.decode(parts[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("user_id")
    username = payload.get("username")
    if user_id is None or username is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"user_id": user_id, "username": username, "role": payload.get("role")}


def require_admin(current_user: dict = Depends(get_current_user)):
    """Dependency for admin-only endpoints"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ========================
# 1. Auth
# ========================
@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, http_request: Request, db: Session = Depends(get_db)):
    """Login: blocks an IP after 10 failures for 1 hour, issues JWT on success."""
    client_ip = http_request.client.host if http_request.client else "unknown"

    # Check block status
    if client_ip in login_attempts:
        attempts, last_attempt = login_attempts[client_ip]
        if datetime.now() - last_attempt >= BLOCK_DURATION:
            del login_attempts[client_ip]
        elif attempts >= MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    # Fetch user info from database
    result = db.execute(
        text("SELECT id, username, password_hash, role FROM users WHERE username = :username"),
        {"username": payload.username},
    ).fetchone()

    if result is None:
        record_failure(client_ip)  # Record failed login attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_id, username, password_hash, role = result

    # Verify password
    try:
        valid = pwd_context.verify(payload.password, password_hash)
    except Exception:
        valid = False

    if not valid:
        record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Success - clear failed login attempts
    login_attempts.pop(client_ip, None)

    token = create_access_token({"user_id": user_id, "username": username, "role": role})
    return LoginResponse(access_token=token, token_type="bearer", role=role, username=username)


@app.get("/api/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get info of the logged-in user"""
    result = db.execute(
        text("SELECT * FROM users WHERE id = :user_id"),
        {"user_id": current_user["user_id"]},
    ).fetchone()

    if result is None:
        raise HTTPException(status_code=404, detail="User not found")

    data = result._mapping
    return UserResponse(
        id=data["id"],
        username=data["username"],
        role=data["role"],
        created_at=data.get("created_at"),
    )

# ========================
# 1-1. VLAN 2-Step Authentication
# ========================
class ValidateVLANRequest(BaseModel):
    username: str
    vlan_code: str


@app.post("/api/auth/validate-vlan")
def validate_vlan(request: ValidateVLANRequest, current_user: dict = Depends(get_current_user)):
    """Reissue JWT token containing VLAN zone info after selection"""
    token = create_access_token({
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "vlan": request.vlan_code
    })
    return {
        "message": f"Successfully entered zone {request.vlan_code}.",
        "access_token": token,
        "token_type": "bearer",
        "username": current_user["username"],
        "vlan_code": request.vlan_code,
        "role": current_user["role"]
    }
    

# ========================
# 2. Devices
# ========================
@app.get("/api/devices")
def get_devices(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all network devices (auth required)"""
    rows = db.execute(text("SELECT * FROM devices ORDER BY id")).fetchall()
    return {"devices": [row_to_dict(r) for r in rows]}


@app.post("/api/devices")
def create_device(device: dict, current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Add a new network device (admin only)"""
    db.execute(
        text("""
            INSERT INTO devices (ip_address, device_name, device_type, vlan, owner, status)
            VALUES (:ip, :name, :type, :vlan, :owner, :status)
        """),
        {
            "ip": device.get("ip_address"),
            "name": device.get("device_name"),
            "type": device.get("device_type"),
            "vlan": device.get("vlan"),
            "owner": device.get("owner"),
            "status": device.get("status", "active"),
        },
    )
    db.commit()
    return {"message": "Device added successfully"}


# ========================
# 3. Telemetry (table: telemetry)
# ========================
@app.get("/api/telemetry/latest")
def get_latest_telemetry(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Latest telemetry data (auth required)"""
    rows = db.execute(text("SELECT * FROM telemetry ORDER BY id DESC LIMIT 50")).fetchall()
    return {"telemetry": [row_to_dict(r) for r in rows]}


# ========================
# 4. Alerts (table: alerts)
# ========================
@app.get("/api/alerts")
def get_alerts(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Latest AI analysis alerts (auth required)"""
    rows = db.execute(text("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")).fetchall()
    return {"alerts": [row_to_dict(r) for r in rows]}
    

# ========================
# 5. Endpoint security events
# ========================
@app.get("/api/endpoint-security/events")
def get_endpoint_events(
    since: int = 0,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Called by pollEndpointSecurity() in the frontend. Returns events with id > since."""
    rows = db.execute(
        text("""
            SELECT id, action, process_name, pid, reason, created_at AS time
            FROM endpoint_events
            WHERE id > :since
            ORDER BY id ASC
            LIMIT 50
        """),
        {"since": since},
    ).fetchall()
    return [row_to_dict(r) for r in rows]


@app.post("/api/endpoint-security/events")
def create_endpoint_event(event: dict, x_api_key: str = Header(None), db: Session = Depends(get_db)):
    """
    Create endpoint security event (for agent). Header: X-API-Key
    Body: {"action": "blocked"|"allowed", "process_name": "...", "pid": 1234, "reason": "..."}
    """
    if x_api_key != AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Normalize action values (block -> blocked, allow -> allowed)
    action = str(event.get("action", "")).lower()
    action = {"block": "blocked", "allow": "allowed"}.get(action, action)

    result = db.execute(
        text("""
            INSERT INTO endpoint_events (action, process_name, pid, reason)
            VALUES (:action, :process_name, :pid, :reason)
        """),
        {
            "action": action,
            "process_name": event.get("process_name"),
            "pid": event.get("pid"),
            "reason": event.get("reason"),
        },
    )
    db.commit()
    return {"id": result.lastrowid, "message": "Event recorded"}


# ========================
# 6. Health / Admin
# ========================
@app.get("/api/health")
def health_check():
    """Health check (no auth)"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/admin/db-test")
def db_test(current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Check DB connection (admin only)"""
    try:
        db.execute(text("SELECT 1")).fetchone()
        return {"status": "connected", "db": "MySQL", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB connection error: {str(e)}")


# ========================
# Static files (MUST be registered last, otherwise it shadows /api routes)
# ========================
PUBLIC_DIR = BASE_DIR.parent.parent / "public"  
if PUBLIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(PUBLIC_DIR), html=True), name="static")
else:
    print(f"[!] Static dir not found, skipping: {PUBLIC_DIR}")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)