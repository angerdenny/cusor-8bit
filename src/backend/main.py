# -*- coding: utf-8 -*-
import os
import hmac
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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

import ipaddress
from sqlalchemy import bindparam
from ai_routes import build_ai_router, score_rows 

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
class ValidateVLANRequest(BaseModel):
    username: str | None = None
    vlan_code: str

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
    vlan_code: str | None = None
    vlan_name: str | None = None

class DeviceCreate(BaseModel):
    name: str
    ip: str
    type: str
    vlan_code: str
    owner_id: int | None = None
    x: float = 0
    y: float = 0


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

    return {
        "user_id": user_id,
        "username": username,
        "role": payload.get("role"),
        "vlan": payload.get("vlan"),
    }


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
    username = payload.username.strip()
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
        {"username": username},
    ).fetchone()

    if result is None:
        record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_id, username, password_hash, role = result

    # Verify password (a broken hash counts as a failed login, not a 500)
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
    """Get info of the logged-in user (includes VLAN zone from token)"""
    result = db.execute(
        text("SELECT id, username, role, created_at FROM users WHERE id = :user_id"),
        {"user_id": current_user["user_id"]},
    ).fetchone()

    if result is None:
        raise HTTPException(status_code=404, detail="User not found")

    data = result._mapping
    vlan_code = current_user.get("vlan")
    vlan_name = None
    if vlan_code:
        v = db.execute(
            text("SELECT name FROM vlans WHERE code = :code"), {"code": vlan_code}
        ).fetchone()
        vlan_name = v[0] if v else None

    return UserResponse(
        id=data["id"],
        username=data["username"],
        role=data["role"],
        created_at=data["created_at"],
        vlan_code=vlan_code,
        vlan_name=vlan_name,
    )


@app.post("/api/auth/validate-vlan")
def validate_vlan(
    request: ValidateVLANRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Verify the zone code against the vlans table and check user permissions.
    Reissue JWT with the zone information.
    """
    # Step 1: Verify zone code exists in vlans table
    vlan = db.execute(
        text("SELECT id, name, code FROM vlans WHERE code = :code"),
        {"code": request.vlan_code},
    ).fetchone()
    if vlan is None:
        raise HTTPException(status_code=403, detail="Invalid zone code")
    

    # Step 2: Admin can enter every zone, others need a user_vlans row
    if current_user.get("role") != "admin":
        user_vlan = db.execute(
            text("""
                SELECT access_level FROM user_vlans
                WHERE user_id = :user_id AND vlan_id = :vlan_id
            """),
            {"user_id": current_user["user_id"], "vlan_id": vlan.id},
        ).fetchone()
        if user_vlan is None:
            raise HTTPException(status_code=403, detail="No access to this zone")

    # Step 3: Reissue access token
    token = create_access_token({
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "vlan": vlan.code,
    })
    return {
        "message": f"Successfully entered zone {vlan.code}.",
        "access_token": token,
        "token_type": "bearer",
        "username": current_user["username"],
        "vlan_code": vlan.code,
        "vlan_name": vlan.name,
        "role": current_user["role"],
    }
@app.get("/api/auth/my-zones")
def my_zones(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Zones the logged-in user may enter (admin = all zones)."""
    if current_user.get("role") == "admin":
        rows = db.execute(text("SELECT id, name, code FROM vlans ORDER BY id")).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT v.id, v.name, v.code
                FROM vlans v JOIN user_vlans uv ON uv.vlan_id = v.id
                WHERE uv.user_id = :uid ORDER BY v.id
            """),
            {"uid": current_user["user_id"]},
        ).fetchall()
    return {"zones": [row_to_dict(r) for r in rows]}


# ========================
# 2-0. Device Enrollment & Dashboard
# ========================
@app.get("/api/devices/pending")
def get_pending_devices(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Get devices waiting for enrollment (status='pending')"""
    rows = db.execute(
        text("""
            SELECT id, name, ip, type, vlan_id, owner_id, x, y, status, created_at
            FROM devices
            WHERE status = 'pending'
            ORDER BY created_at DESC
        """)
    ).fetchall()
    return {"pending_devices": [row_to_dict(r) for r in rows]}


@app.post("/api/devices/enroll")
def enroll_device(
    device_id: int,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Move device from pending to registered"""
    device = db.execute(
        text("SELECT id, status FROM devices WHERE id = :id"),
        {"id": device_id},
    ).fetchone()
    
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if device.status != "pending":
        raise HTTPException(status_code=400, detail="Device is not in pending status")
    
    db.execute(
        text("UPDATE devices SET status = 'registered' WHERE id = :id"),
        {"id": device_id},
    )
    db.commit()
    return {"id": device_id, "message": "Device enrolled successfully", "status": "registered"}


@app.get("/api/dashboard/overview")
def get_dashboard_overview(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get overview for root dashboard (all zones + all devices stats).
    Regular users see only their assigned zones.
    """
    is_admin = current_user.get("role") == "admin"
    
    # Get zones (admin = all, user = assigned)
    if is_admin:
        zone_rows = db.execute(
            text("SELECT id, name, code FROM vlans ORDER BY id")
        ).fetchall()
    else:
        zone_rows = db.execute(
            text("""
                SELECT v.id, v.name, v.code
                FROM vlans v JOIN user_vlans uv ON uv.vlan_id = v.id
                WHERE uv.user_id = :uid
                ORDER BY v.id
            """),
            {"uid": current_user["user_id"]},
        ).fetchall()
    
    zones = [row_to_dict(r) for r in zone_rows]
    zone_ids = [z["id"] for z in zones]
    
    # Get devices per zone
    zone_stats = []
    total_cpu = total_ram = total_traffic = 0
    total_devices = 0
    
    for zone in zones:
        device_rows = db.execute(
            text("""
                SELECT d.id, d.name, d.ip, d.type, d.vlan_id, d.status,
                       COALESCE(MAX(t.cpu), 0) AS cpu,
                       COALESCE(MAX(t.ram), 0) AS ram,
                       COALESCE(MAX(t.traffic_in), 0) AS traffic
                FROM devices d
                LEFT JOIN telemetry t ON t.device_id = d.id
                WHERE d.vlan_id = :vlan_id AND d.status = 'registered'
                GROUP BY d.id
            """),
            {"vlan_id": zone["id"]},
        ).fetchall()
        
        devices = [row_to_dict(r) for r in device_rows]
        zone_cpu = sum(d.get("cpu", 0) for d in devices)
        zone_ram = sum(d.get("ram", 0) for d in devices)
        zone_traffic = sum(d.get("traffic", 0) for d in devices)
        
        total_cpu += zone_cpu
        total_ram += zone_ram
        total_traffic += zone_traffic
        total_devices += len(devices)
        
        zone_stats.append({
            "zone_id": zone["id"],
            "zone_name": zone["name"],
            "zone_code": zone["code"],
            "device_count": len(devices),
            "avg_cpu": zone_cpu / len(devices) if devices else 0,
            "avg_ram": zone_ram / len(devices) if devices else 0,
            "total_traffic": zone_traffic,
            "devices": devices,
        })
    
    # Get alerts
    alert_rows = db.execute(
        text("""
            SELECT id, title, description, severity, created_at
            FROM alerts
            WHERE severity IN ('critical', 'warning')
            ORDER BY created_at DESC
            LIMIT 10
        """)
    ).fetchall()
    alerts = [row_to_dict(a) for a in alert_rows]
    
    return {
        "zones": zones,
        "zone_stats": zone_stats,
        "summary": {
            "total_zones": len(zones),
            "total_devices": total_devices,
            "avg_cpu": total_cpu / total_devices if total_devices > 0 else 0,
            "avg_ram": total_ram / total_devices if total_devices > 0 else 0,
            "total_traffic": total_traffic,
            "critical_alerts": len([a for a in alerts if a.get("severity") == "critical"]),
        },
        "recent_alerts": alerts,
    }   

# ========================
# 2. Devices
# ========================
ALLOWED_DEVICE_TYPES = {
    "router", "switch", "server", "app", "pc",
    "mobile", "firewall", "printer", "access-point",
}
POS_MIN, POS_MAX = -50, 150  # schema.sql 의 ck_devices_x / ck_devices_y 범위와 동일


class DeviceUpdate(BaseModel):
    name: str | None = None
    ip: str | None = None
    type: str | None = None
    vlan_code: str | None = None
    owner_id: int | None = None
    x: float | None = None
    y: float | None = None


def _clean_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="IP 형식이 올바르지 않습니다")


def _clean_type(device_type: str) -> str:
    if device_type not in ALLOWED_DEVICE_TYPES:
        raise HTTPException(status_code=400, detail="지원하지 않는 장비 종류입니다")
    return device_type


def _check_xy(x, y):
    if (x is None) != (y is None):
        raise HTTPException(status_code=400, detail="x와 y는 함께 지정해야 합니다")
    for v in (x, y):
        if v is not None and not (POS_MIN <= v <= POS_MAX):
            raise HTTPException(status_code=400, detail=f"좌표는 {POS_MIN}~{POS_MAX} 범위여야 합니다")

def _vlan_integrity_detail(e: IntegrityError) -> str:
    msg = str(getattr(e, "orig", e)).lower()
    if "duplicate" in msg and "code" in msg:
        return "이미 사용 중인 구역 코드입니다"
    if "duplicate" in msg and "name" in msg:
        return "이미 사용 중인 구역 이름입니다"
    return "VLAN 정보가 올바르지 않습니다"
    
def _integrity_detail(e: IntegrityError) -> str:
    msg = str(e.orig)
    if "ux_devices_ip" in msg or "Duplicate" in msg:
        return "이미 등록된 IP입니다"
    if "fk_devices_owner" in msg or "foreign key" in msg.lower():
        return "소유자 정보가 올바르지 않습니다"
    return "장비 정보가 올바르지 않습니다"


@app.get("/api/devices")
def get_devices(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Frontend loadDevices() 용: {vlans, devices, links}.
    admin = 전체, 일반 사용자 = user_vlans 에 등록된 구역의 데이터만.
    """
    if current_user.get("role") == "admin":
        vlan_rows = db.execute(text(
            "SELECT id, code, name, cidr, color FROM vlans ORDER BY id"
        )).fetchall()
    else:
        vlan_rows = db.execute(
            text("""
                SELECT v.id, v.code, v.name, v.cidr, v.color
                FROM vlans v
                JOIN user_vlans uv ON uv.vlan_id = v.id
                WHERE uv.user_id = :uid
                ORDER BY v.id
            """),
            {"uid": current_user["user_id"]},
        ).fetchall()

    vlan_ids = [r.id for r in vlan_rows]
    if not vlan_ids:
        return {"vlans": [], "devices": [], "links": []}

    device_rows = db.execute(
        text("""
            SELECT d.id, d.name, d.ip, d.type, d.owner_id, d.x, d.y, d.vlan_id,
                   v.code AS vlan_code, u.username AS owner
            FROM devices d
            JOIN vlans v ON v.id = d.vlan_id
            LEFT JOIN users u ON u.id = d.owner_id
            WHERE d.vlan_id IN :vlan_ids
            ORDER BY d.id
        """).bindparams(bindparam("vlan_ids", expanding=True)),
        {"vlan_ids": vlan_ids},
    ).fetchall()

    device_ids = [r.id for r in device_rows]
    link_rows = []
    if device_ids:
        link_rows = db.execute(
            text("""
                SELECT source_id, target_id FROM links
                WHERE source_id IN :ids AND target_id IN :ids
            """).bindparams(bindparam("ids", expanding=True)),
            {"ids": device_ids},
        ).fetchall()

    return {
        "vlans": [row_to_dict(r) for r in vlan_rows],
        "devices": [row_to_dict(r) for r in device_rows],
        "links": [row_to_dict(r) for r in link_rows],
    }

@app.get("/api/users")
def get_users(current_user: dict = Depends(get_current_user)):
    """사용자 목록 반환"""
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, username FROM users")).fetchall()
        return {"users": [{"id": r[0], "username": r[1]} for r in rows]}

# ========================
# 2. VLAN CRUD
# ========================

class VLANCreate(BaseModel):
    name: str
    code: str
    cidr: str
    color: str

@app.get("/api/vlans")
def get_vlans(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """모든 VLAN 조회"""
    vlans = db.execute(text("SELECT id, name, code, cidr, color FROM vlans ORDER BY id")).fetchall()
    return {"vlans": [row_to_dict(r) for r in vlans]}

@app.post("/api/vlans")
def create_vlan(vlan: VLANCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """새 VLAN 생성 (admin only)"""
    try:
        result = db.execute(
            text("INSERT INTO vlans (name, code, cidr, color) VALUES (:name, :code, :cidr, :color)"),
            {"name": vlan.name, "code": vlan.code, "cidr": vlan.cidr, "color": vlan.color}
        )
        db.commit()
        return {"id": result.lastrowid, "message": "VLAN created successfully"}
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=_vlan_integrity_detail(e))

@app.put("/api/vlans/{vlan_id}")
def update_vlan(vlan_id: int, vlan: VLANCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """VLAN 수정 (admin only)"""
    if db.execute(text("SELECT id FROM vlans WHERE id = :id"), {"id": vlan_id}).fetchone() is None:
        raise HTTPException(status_code=404, detail="VLAN not found")
    
    db.execute(
        text("UPDATE vlans SET name = :name, code = :code, cidr = :cidr, color = :color WHERE id = :id"),
        {"id": vlan_id, "name": vlan.name, "code": vlan.code, "cidr": vlan.cidr, "color": vlan.color}
    )
    db.commit()
    return {"id": vlan_id, "message": "VLAN updated successfully"}

@app.delete("/api/vlans/{vlan_id}")
def delete_vlan(vlan_id: int, current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """VLAN 삭제 (admin only)"""
    if db.execute(text("SELECT id FROM vlans WHERE id = :id"), {"id": vlan_id}).fetchone() is None:
        raise HTTPException(status_code=404, detail="VLAN not found")
    
    db.execute(text("DELETE FROM vlans WHERE id = :id"), {"id": vlan_id})
    db.commit()
    return {"id": vlan_id, "message": "VLAN deleted successfully"}

@app.post("/api/devices")
def create_device(device: DeviceCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Add a new network device (admin only)"""
    name = device.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="장비 이름을 입력해 주세요")
    ip = _clean_ip(device.ip)
    dtype = _clean_type(device.type)
    _check_xy(device.x, device.y)

    vlan = db.execute(
        text("SELECT id FROM vlans WHERE code = :code"), {"code": device.vlan_code}
    ).fetchone()
    if vlan is None:
        raise HTTPException(status_code=400, detail="Unknown vlan_code")

    try:
        result = db.execute(
            text("""
                INSERT INTO devices (name, ip, type, owner_id, x, y, vlan_id)
                VALUES (:name, :ip, :type, :owner_id, :x, :y, :vlan_id)
            """),
            {"name": name, "ip": ip, "type": dtype,
             "owner_id": device.owner_id or current_user["user_id"],
             "x": device.x, "y": device.y, "vlan_id": vlan[0]},
        )
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=_integrity_detail(e))
    return {"id": result.lastrowid, "message": "Device added successfully"}


@app.put("/api/devices/{device_id}")
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Update a device (admin only). 보낸 필드만 수정됩니다."""
    data = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") \
        else payload.dict(exclude_unset=True)
    if not data:
        raise HTTPException(status_code=400, detail="변경할 내용이 없습니다")

    if db.execute(text("SELECT id FROM devices WHERE id = :id"), {"id": device_id}).fetchone() is None:
        raise HTTPException(status_code=404, detail="Device not found")

    sets, params = [], {"id": device_id}

    if "name" in data:
        name = (data["name"] or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="장비 이름을 입력해 주세요")
        sets.append("name = :name"); params["name"] = name
    if "ip" in data:
        sets.append("ip = :ip"); params["ip"] = _clean_ip(data["ip"] or "")
    if "type" in data:
        sets.append("type = :type"); params["type"] = _clean_type(data["type"] or "")
    if "vlan_code" in data:
        vlan = db.execute(
            text("SELECT id FROM vlans WHERE code = :code"), {"code": data["vlan_code"]}
        ).fetchone()
        if vlan is None:
            raise HTTPException(status_code=400, detail="Unknown vlan_code")
        sets.append("vlan_id = :vlan_id"); params["vlan_id"] = vlan[0]
    if "owner_id" in data:
        sets.append("owner_id = :owner_id"); params["owner_id"] = data["owner_id"]
    if "x" in data or "y" in data:
        x, y = data.get("x"), data.get("y")
        _check_xy(x, y)
        sets.append("x = :x"); params["x"] = x
        sets.append("y = :y"); params["y"] = y

    try:
        db.execute(text(f"UPDATE devices SET {', '.join(sets)} WHERE id = :id"), params)
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=_integrity_detail(e))
    return {"id": device_id, "message": "Device updated successfully"}


@app.delete("/api/devices/{device_id}")
def delete_device(
    device_id: int,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Delete a device (admin only). links / telemetry / alert_devices 는 FK CASCADE 로 함께 삭제됩니다."""
    if db.execute(text("SELECT id FROM devices WHERE id = :id"), {"id": device_id}).fetchone() is None:
        raise HTTPException(status_code=404, detail="Device not found")
    db.execute(text("DELETE FROM devices WHERE id = :id"), {"id": device_id})
    db.commit()
    return {"id": device_id, "message": "Device deleted successfully"}

# ========================
# 2-1. Links (device connections)
# ========================
class LinkPayload(BaseModel):
    source_id: int
    target_id: int
 
 
@app.post("/api/links")
def create_link(
    payload: LinkPayload,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Connect two devices (admin only). schema.sql 주석대로 자기 자신/중복(A-B, B-A)은 여기서 검사."""
    a, b = payload.source_id, payload.target_id
    if a == b:
        raise HTTPException(status_code=400, detail="같은 장비끼리는 연결할 수 없습니다")
 
    found = db.execute(
        text("SELECT COUNT(*) FROM devices WHERE id IN :ids").bindparams(
            bindparam("ids", expanding=True)
        ),
        {"ids": [a, b]},
    ).scalar()
    if found != 2:
        raise HTTPException(status_code=404, detail="Device not found")
 
    dup = db.execute(
        text("""
            SELECT 1 FROM links
            WHERE (source_id = :a AND target_id = :b)
               OR (source_id = :b AND target_id = :a)
        """),
        {"a": a, "b": b},
    ).fetchone()
    if dup:
        raise HTTPException(status_code=400, detail="이미 연결되어 있는 장비입니다")
 
    try:
        db.execute(
            text("INSERT INTO links (source_id, target_id) VALUES (:a, :b)"),
            {"a": a, "b": b},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="연결 정보가 올바르지 않습니다")
    return {"message": "Link created successfully"}
 
 
@app.delete("/api/links")
def delete_link(
    source_id: int,
    target_id: int,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Disconnect two devices (admin only). 방향(A-B / B-A)과 상관없이 삭제."""
    result = db.execute(
        text("""
            DELETE FROM links
            WHERE (source_id = :a AND target_id = :b)
               OR (source_id = :b AND target_id = :a)
        """),
        {"a": source_id, "b": target_id},
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"message": "Link deleted successfully"}
    
# ========================
# 3. Telemetry (table: telemetry)
# ========================
@app.get("/api/telemetry/latest")
def get_latest_telemetry(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Latest telemetry data + AI risk score (auth required)"""
    rows = db.execute(text("SELECT * FROM telemetry ORDER BY id DESC LIMIT 50")).fetchall()
    data = [row_to_dict(r) for r in rows]
    return {"telemetry": score_rows(db, data)}


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
    if not x_api_key or not hmac.compare_digest(x_api_key, AGENT_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API Key")

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


app.include_router(build_ai_router(get_db, get_current_user, require_admin, AGENT_API_KEY))
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
