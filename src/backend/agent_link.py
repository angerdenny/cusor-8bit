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

PAIR_TTL = 600  # 연결 코드 유효 시간(초)
DEFAULT_VLAN_ID = int(os.getenv("DEFAULT_VLAN_ID", "1"))

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
        # 2단계(구역 선택)에서 막히지 않도록 기본 구역 조회 권한을 함께 준다
        db.execute(
            text("INSERT INTO user_vlans (user_id, vlan_id, access_level) VALUES (:u, :v, 'view')"),
            {"u": result.lastrowid, "v": DEFAULT_VLAN_ID},
        )
        db.commit()
        return {"ok": True, "username": body.username}

    @router.post("/api/agent/pair-request", dependencies=[Depends(agent_auth)])
    def pair_request(body: PairReq, db=Depends(get_db)):
        row = db.execute(text("SELECT id, owner_id FROM devices WHERE client_uuid=:c"),
                         {"c": body.agent_id}).first()
        if row and row.owner_id:
            return {"linked": True, "device_id": row.id}

        with _pair_lock:
            _cleanup()
            for code, v in _pairs.items():
                if v["agent_id"] == body.agent_id:          # 같은 PC는 같은 코드 재사용
                    return {"linked": False, "code": code, "expires_in": int(v["expires"] - time.time())}
            while True:
                code = f"{secrets.randbelow(10**6):06d}"
                if code not in _pairs:
                    break
            _pairs[code] = {"agent_id": body.agent_id, "name": body.name or "PC",
                            "ip": body.ip or "0.0.0.0", "expires": time.time() + PAIR_TTL}
        return {"linked": False, "code": code, "expires_in": PAIR_TTL}

    @router.post("/api/link/claim")
    def claim(body: ClaimReq, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
        uid = current_user["user_id"]
        if not db.execute(text("SELECT 1 FROM users WHERE id=:u"), {"u": uid}).first():
            raise HTTPException(status_code=401, detail="계정이 없습니다. 다시 로그인하세요")
        with _pair_lock:
            _cleanup()
            pending = _pairs.get(body.code)
            if not pending:
                raise HTTPException(status_code=404, detail="코드가 없거나 만료되었습니다")

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
