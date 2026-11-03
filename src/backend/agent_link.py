"""다른 PC 연결 모듈
- POST /api/auth/register        : 사용자 회원가입 (role=user 고정)
- POST /api/agent/pair-request   : 에이전트가 연결 코드를 받음 (AGENT_API_KEY)
- POST /api/link/claim           : 로그인한 사용자가 코드를 입력해 PC를 본인에게 연결
- POST /api/agent/telemetry      : 에이전트가 CPU/메모리/트래픽을 API로 보고 (DB 비밀번호 불필요)
"""
import hmac
import os
import random
import secrets
import threading
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text

PAIR_TTL = 1800  # 연결 코드 유효 시간(초). 컬렉터가 켜져 있는 동안은 계속 연장된다
DEFAULT_VLAN_ID = int(os.getenv("DEFAULT_VLAN_ID", "1"))
ADMIN_AGENT_IDS = {x.strip() for x in os.getenv("ADMIN_AGENT_IDS", "").split(",") if x.strip()}
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").strip()

_pairs: dict[str, dict] = {}      # code -> {agent_id, name, ip, expires}
_pair_lock = threading.Lock()
_reg_hits: dict[str, list] = {}   # 가입 요청 횟수 제한 (IP별)
REG_LIMIT, REG_WINDOW = 5, 600


class RegisterReq(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=64)


class PairReq(BaseModel):
    agent_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    name: str = Field(default="", max_length=100)
    ip: str = Field(default="", max_length=45)


class ClaimReq(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class UserIdReq(BaseModel):
    user_id: int


class PcApproveReq(BaseModel):
    ref: str = Field(min_length=4, max_length=32, pattern=r"^[A-Za-z0-9-]+$")
    user_id: int


class WithdrawReq(BaseModel):
    password: str = Field(min_length=1, max_length=64)


class TelemetryReq(BaseModel):
    agent_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    cpu_usage: float = Field(ge=0, le=100)
    ram_usage: float = Field(ge=0, le=100)
    traffic_in_mbps: float = Field(default=0, ge=0)
    packet_loss: float = Field(default=0, ge=0, le=100)


def build_link_router(get_db, get_current_user, pwd_context, agent_key: str):
    router = APIRouter()

    def agent_auth(x_api_key: str = Header(default="")):
        if not hmac.compare_digest(x_api_key, agent_key):
            raise HTTPException(status_code=401, detail="에이전트 인증 실패")

    def _cleanup():
        now = time.time()
        for code in [c for c, v in _pairs.items() if v["expires"] < now]:
            _pairs.pop(code, None)

    @router.post("/api/auth/register", status_code=201)
    def register(body: RegisterReq, request: Request, db=Depends(get_db)):
        if len(body.password.encode("utf-8")) > 72:
            raise HTTPException(status_code=400, detail="비밀번호가 너무 깁니다")

        # 가입 스팸 방지 (프록시 뒤라서 X-Forwarded-For 첫 값 사용)
        fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        ip = fwd or (request.client.host if request.client else "unknown")
        now = time.time()
        hits = [t for t in _reg_hits.get(ip, []) if now - t < REG_WINDOW]
        if len(hits) >= REG_LIMIT:
            raise HTTPException(status_code=429, detail="가입 요청이 너무 많습니다. 잠시 후 다시 시도하세요")
        hits.append(now)
        _reg_hits[ip] = hits

        if db.execute(text("SELECT id FROM users WHERE username=:u"), {"u": body.username}).first():
            raise HTTPException(status_code=409, detail="이미 사용 중인 아이디입니다")

        result = db.execute(
            text("INSERT INTO users (username, password_hash, role) VALUES (:u, :h, 'user')"),
            {"u": body.username, "h": pwd_context.hash(body.password)},
        )
        # 구역 접근은 관리자가 승인(/api/access/approve-user)해야 열린다. 그 전까지는 user_vlans 행이 없다
        db.commit()
        return {"ok": True, "username": body.username}

    @router.post("/api/agent/pair-request", dependencies=[Depends(agent_auth)])
    def pair_request(body: PairReq, db=Depends(get_db)):
        row = db.execute(text("SELECT id, owner_id FROM devices WHERE client_uuid=:c"),
                         {"c": body.agent_id}).first()
        if body.agent_id in ADMIN_AGENT_IDS:   # 관리자 노트북: 코드 입력 없이 항상 관리자 소유로 연결
            if ADMIN_USERNAME:
                admin = db.execute(text("SELECT id FROM users WHERE username=:u AND role='admin'"),
                                   {"u": ADMIN_USERNAME}).first()
            else:
                admin = db.execute(text("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")).first()
            if admin:
                if row:
                    if row.owner_id != admin.id:
                        db.execute(text("UPDATE devices SET owner_id=:u WHERE id=:id"), {"u": admin.id, "id": row.id})
                        db.commit()
                    return {"linked": True, "device_id": row.id}
                result = db.execute(
                    text("""INSERT INTO devices (name, ip, type, owner_id, x, y, client_uuid, vlan_id)
                            VALUES (:n,:ip,'pc',:u,:x,:y,:c,:v)"""),
                    {"n": body.name or "관리자 노트북", "ip": body.ip or "0.0.0.0", "u": admin.id,
                     "x": random.uniform(15, 85), "y": random.uniform(15, 85),
                     "c": body.agent_id, "v": DEFAULT_VLAN_ID})
                db.commit()
                return {"linked": True, "device_id": result.lastrowid}

        if row and row.owner_id:
            return {"linked": True, "device_id": row.id}

        with _pair_lock:
            _cleanup()
            for code, v in _pairs.items():
                if v["agent_id"] == body.agent_id:          # 같은 PC는 같은 코드 재사용
                    v["expires"] = time.time() + PAIR_TTL    # 컬렉터가 켜져 있는 동안 승인 대기 유지
                    return {"linked": False, "code": code, "expires_in": PAIR_TTL}
            while True:
                code = f"{secrets.randbelow(10**6):06d}"
                if code not in _pairs:
                    break
            _pairs[code] = {"agent_id": body.agent_id, "name": body.name or "PC",
                            "ip": body.ip or "0.0.0.0", "expires": time.time() + PAIR_TTL,
                            "approved_user": None}   # 관리자가 승인한 사용자 id (승인 전에는 None)
        return {"linked": False, "code": code, "expires_in": PAIR_TTL}

    @router.post("/api/link/claim")
    def claim(body: ClaimReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        uid = current_user["user_id"]
        if not db.execute(text("SELECT 1 FROM users WHERE id=:u"), {"u": uid}).first():
            raise HTTPException(status_code=401, detail="계정이 없습니다. 다시 로그인하세요")
        with _pair_lock:
            _cleanup()
            pending = _pairs.get(body.code)
            # 코드 존재 여부가 드러나지 않도록, 없는 코드와 승인되지 않은 코드는 같은 메시지로 거절한다
            if not pending or (current_user.get("role") != "admin" and pending.get("approved_user") != uid):
                raise HTTPException(status_code=404, detail="코드가 없거나 관리자 승인이 필요합니다")

        existing = db.execute(text("SELECT id, owner_id FROM devices WHERE client_uuid=:c"),
                              {"c": pending["agent_id"]}).first()
        if existing:
            if existing.owner_id and existing.owner_id != uid:
                raise HTTPException(status_code=409, detail="이미 다른 사용자에게 연결된 PC입니다")
            db.execute(text("UPDATE devices SET owner_id=:u WHERE id=:id"), {"u": uid, "id": existing.id})
            device_id = existing.id
        else:
            # 토폴로지에 그려지도록 좌표를 함께 넣는다 (좌표가 없으면 화면에 안 보임)
            result = db.execute(
                text("""INSERT INTO devices (name, ip, type, owner_id, x, y, client_uuid, vlan_id)
                        VALUES (:n, :ip, 'pc', :u, :x, :y, :c, :v)"""),
                {"n": pending["name"], "ip": pending["ip"], "u": uid,
                 "x": random.uniform(15, 85), "y": random.uniform(15, 85),
                 "c": pending["agent_id"], "v": DEFAULT_VLAN_ID},
            )
            device_id = result.lastrowid
        db.commit()

        with _pair_lock:
            _pairs.pop(body.code, None)
        return {"ok": True, "device_id": device_id, "name": pending["name"]}

    @router.get("/api/link/pending")
    def pending_pcs(current_user: dict = Depends(get_current_user)):
        """코드 입력을 기다리는 PC 목록. 관리자는 전체, 일반 사용자는 관리자가 본인에게 승인한 PC만 본다.
        (연결 코드는 보여주지 않는다)"""
        now = time.time()
        is_admin = current_user.get("role") == "admin"
        with _pair_lock:
            _cleanup()
            items = [{"name": v["name"], "ip": v["ip"], "expires_in": int(v["expires"] - now)}
                     for v in _pairs.values()
                     if is_admin or v.get("approved_user") == current_user["user_id"]]
        return {"pending": items}

    # ---------- 관리자 승인 (가입 구역 접근 / 새 PC 연결) ----------
    def _need_admin(u: dict):
        if u.get("role") != "admin":
            raise HTTPException(status_code=403, detail="관리자만 사용할 수 있습니다")

    @router.get("/api/access/requests")
    def access_requests(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        """관리자 승인 대기 목록: 구역 권한이 없는 신규 사용자 + 아직 누구에게도 승인되지 않은 PC"""
        _need_admin(current_user)
        users = db.execute(text(
            "SELECT u.id, u.username FROM users u WHERE u.role='user' "
            "AND NOT EXISTS (SELECT 1 FROM user_vlans uv WHERE uv.user_id=u.id) ORDER BY u.id")).fetchall()
        with _pair_lock:
            _cleanup()
            pcs = [{"ref": v["agent_id"][:12], "name": v["name"], "ip": v["ip"]}
                   for v in _pairs.values() if v.get("approved_user") is None]
        return {"users": [{"id": x.id, "username": x.username} for x in users], "pcs": pcs}

    @router.post("/api/access/approve-user")
    def approve_user(body: UserIdReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        _need_admin(current_user)
        if not db.execute(text("SELECT 1 FROM users WHERE id=:u AND role='user'"), {"u": body.user_id}).first():
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")
        db.execute(text("INSERT INTO user_vlans (user_id, vlan_id, access_level) "
                        "SELECT :u, v.id, 'view' FROM vlans v WHERE NOT EXISTS "
                        "(SELECT 1 FROM user_vlans x WHERE x.user_id=:u AND x.vlan_id=v.id)"), {"u": body.user_id})
        db.commit()
        return {"ok": True}

    @router.post("/api/access/reject-user")
    def reject_user(body: UserIdReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        """가입 거절 = 아직 구역 권한이 없는 일반 사용자 계정 삭제"""
        _need_admin(current_user)
        r = db.execute(text("DELETE FROM users WHERE id=:u AND role='user' "
                            "AND NOT EXISTS (SELECT 1 FROM user_vlans WHERE user_id=:u)"), {"u": body.user_id})
        db.commit()
        if r.rowcount == 0:
            raise HTTPException(status_code=404, detail="삭제할 수 있는 신규 가입자가 아닙니다")
        return {"ok": True}

    @router.post("/api/access/approve-pc")
    def approve_pc(body: PcApproveReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        """새 PC를 특정 사용자에게 승인한다. 그 사용자만 PC 화면의 6자리 코드를 입력해 연결할 수 있다."""
        _need_admin(current_user)
        if not db.execute(text("SELECT 1 FROM users WHERE id=:u"), {"u": body.user_id}).first():
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")
        with _pair_lock:
            _cleanup()
            for v in _pairs.values():
                if v["agent_id"][:12] == body.ref:
                    v["approved_user"] = body.user_id
                    return {"ok": True, "name": v["name"]}
        raise HTTPException(status_code=404, detail="대기 중인 PC가 없거나 만료되었습니다")

    @router.delete("/api/auth/me")
    def withdraw(body: WithdrawReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        """회원 탈퇴. 계정과 구역 권한은 삭제되고, 연결된 PC는 소유자만 비워서 남긴다."""
        if current_user.get("role") == "admin":
            raise HTTPException(status_code=403, detail="관리자 계정은 탈퇴할 수 없습니다")
        uid = current_user["user_id"]
        row = db.execute(text("SELECT password_hash FROM users WHERE id=:u"), {"u": uid}).first()
        if not row:
            raise HTTPException(status_code=404, detail="계정을 찾을 수 없습니다")
        if not pwd_context.verify(body.password, row.password_hash):
            raise HTTPException(status_code=400, detail="비밀번호가 올바르지 않습니다")
        # user_vlans 는 CASCADE, devices.owner_id 는 SET NULL 로 DB가 처리한다
        db.execute(text("DELETE FROM users WHERE id=:u"), {"u": uid})
        db.commit()
        return {"ok": True}

    @router.post("/api/agent/telemetry", dependencies=[Depends(agent_auth)])
    def telemetry(body: TelemetryReq, db=Depends(get_db)):
        row = db.execute(text("SELECT id, owner_id FROM devices WHERE client_uuid=:c"),
                         {"c": body.agent_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="연결되지 않은 PC입니다")
        if not row.owner_id:
            raise HTTPException(status_code=403, detail="사용자에게 아직 연결되지 않았습니다")
        db.execute(
            text("""INSERT INTO telemetry (device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss)
                    VALUES (:d, :c, :r, :t, :p)"""),
            {"d": row.id, "c": body.cpu_usage, "r": body.ram_usage,
             "t": body.traffic_in_mbps, "p": body.packet_loss},
        )
        db.commit()
        return {"ok": True}

    return router
