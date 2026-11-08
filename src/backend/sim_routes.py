"""실제 환경 장애 시뮬레이션 + 조치 흐름 (전시용)

[흐름]
 1) 관리자가 대상 장비(예: 아이패드)에 장애를 주입  → 합성 텔레메트리 + AI 경보
 2) 시스템이 상태를 분석해 권장 조치를 제시       → 'block'(연결 차단) 또는 'mitigate'(위험도 완화)
 3) 관리자가 선택                                 → 완화: 트래픽 제한 적용 후 위험도 하락 / 차단: 송수신 차단 상태로 격리
 4) 조치 완료 후 차단 해제                         → 정상 복구
 에이전트를 못 돌리는 기기(폰·아이패드)는 로그인 없이 X-Device-Id 로 자기 상태를 조회한다 (/api/sim/my-status)

[주의] 차단은 이 시스템 안의 '논리적 차단'이다. 실제 공유기·방화벽 제어는 하지 않는다.

- POST /api/sim/inject    {device_id, kind}   관리자
- POST /api/sim/mitigate  {device_id}         관리자
- POST /api/sim/block     {device_id}         관리자
- POST /api/sim/unblock   {device_id}         관리자
- POST /api/sim/reset     {device_id?}        관리자 (생략하면 전체 해제)
- GET  /api/sim/status                        로그인 사용자 (본인에게 보이는 장비만)
- GET  /api/sim/my-status                     로그인 없이 X-Device-Id 로 자기 기기 상태 (등록 대기·거절 포함)
- POST /api/sim/device-inject {kind}          로그인 없이 X-Device-Id 로 '자기 기기'에만 장애 발생 (결정은 관리자만)
- POST /api/sim/reject-request {client_uuid}  관리자: 등록 요청 거절

위치: src/backend/sim_routes.py
"""
import json
import random
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from .ai_routes import _pending, add_alert, to_features, visible_device_ids

SIM_TTL = 600        # 시뮬레이션 자동 종료 시간(초)
INSERT_EVERY = 4     # 장비당 합성 텔레메트리 최소 간격(초)
DEVICE_COOLDOWN = 8  # 기기가 장애 버튼을 다시 누를 수 있기까지 대기(초)
MAX_ACTIVE = 30      # 동시에 진행할 수 있는 시뮬레이션 수
REJECT_TTL = 600     # 거절 안내를 유지하는 시간(초)

PROFILES = {
    "ddos": {
        "label": "DDoS 부하", "cpu": (85, 97), "ram": (70, 85), "traffic": (900, 1400), "loss": (3, 8),
        "recommend": "block",
        "reason": "외부 대량 트래픽이 집중되어 감염·공격 가능성이 높아요. 송수신을 차단하고 점검하는 걸 권장해요.",
        "cause": "외부에서 다량의 위조 트래픽이 집중되어 대역폭과 세션 자원이 고갈되는 상황이에요.",
        "action": "의심 IP 대역을 차단하고 ISP에 트래픽 정화를 요청하세요.",
    },
    "loss": {
        "label": "패킷 손실", "cpu": (30, 45), "ram": (40, 55), "traffic": (80, 160), "loss": (18, 35),
        "recommend": "mitigate",
        "reason": "공격보다는 회선 품질 문제로 보여요. 차단보다 트래픽 제한과 모니터링으로 위험도를 낮추는 걸 권장해요.",
        "cause": "회선 품질 저하나 큐 오버플로우로 패킷이 유실되고 있어요.",
        "action": "회선·케이블 상태를 점검하고 QoS 큐 설정을 조정하세요.",
    },
    "cpu": {
        "label": "CPU 고부하", "cpu": (96, 100), "ram": (80, 92), "traffic": (100, 200), "loss": (0, 2),
        "recommend": "mitigate",
        "reason": "처리 과부하로 보여요. 차단하면 서비스가 끊기니 부하를 줄이는 완화 조치를 권장해요.",
        "cause": "대량 연결 처리로 CPU 점유율이 임계치를 넘어 과부하 상태예요.",
        "action": "불필요한 프로세스와 세션을 정리하고 이중화 경로로 전환하세요.",
    },
    "down": {
        "label": "회선 다운", "cpu": (3, 8), "ram": (30, 38), "traffic": (0, 1), "loss": (100, 100),
        "recommend": "mitigate",
        "reason": "이미 연결이 끊긴 상태라 차단할 대상이 없어요. 재연결을 시도하고 지켜보는 걸 권장해요.",
        "cause": "케이블 단선이나 포트 장애로 회선 연결이 끊어졌어요.",
        "action": "현장 케이블·포트를 확인하고 예비 회선으로 절체하세요.",
    },
    # 완화 조치 후 상태 (정상 범위에 가까운 값)
    "mitigated": {
        "label": "완화 적용", "cpu": (15, 35), "ram": (60, 72), "traffic": (0.02, 0.4), "loss": (0, 0.5),
        "recommend": None, "reason": "", "cause": "", "action": "",
    },
}

_active: dict = {}   # device_id -> {kind, until, started, name, mitigated}
_last_ins: dict = {}
_lock = threading.Lock()
_blocks_ready = False
_rejected: dict = {}   # client_uuid -> 거절한 시각
_dev_cd: dict = {}     # device_id -> 마지막으로 장애 버튼을 누른 시각


def _ensure_blocks(db) -> bool:
    """차단 목록 테이블이 없으면 만든다 (FK 없이 단순 구성). 만들 수 없으면 False."""
    global _blocks_ready
    if _blocks_ready:
        return True
    try:
        db.execute(text("""CREATE TABLE IF NOT EXISTS device_blocks (
            device_id INT PRIMARY KEY,
            reason VARCHAR(200) NOT NULL DEFAULT '',
            blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""))
        db.commit()
        _blocks_ready = True
    except Exception:
        db.rollback()
    return _blocks_ready


def _sample(kind: str) -> dict:
    p = PROFILES[kind]
    u = random.uniform
    return {
        "cpu_usage": round(u(*p["cpu"]), 1),
        "ram_usage": round(u(*p["ram"]), 1),
        "traffic_in_mbps": round(u(*p["traffic"]), 2),
        "packet_loss": round(min(100.0, u(*p["loss"])), 2),
    }


def _insert_telemetry(db, device_id: int, kind: str) -> dict:
    row = _sample(kind)
    db.execute(
        text("INSERT INTO telemetry (device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss) "
             "VALUES (:d,:c,:r,:t,:l)"),
        {"d": device_id, "c": row["cpu_usage"], "r": row["ram_usage"],
         "t": row["traffic_in_mbps"], "l": row["packet_loss"]})
    return row


def apply_active_sims(db) -> None:
    """/api/telemetry/latest 에서 SELECT 하기 전에 호출한다.
    진행 중인 시뮬레이션 장비마다 합성 텔레메트리를 (최소 INSERT_EVERY초 간격으로) 1건씩 넣는다."""
    now = time.time()
    with _lock:
        for d in [d for d, v in _active.items() if v["until"] < now]:
            _active.pop(d, None)                      # 시간 만료
        todo = [(d, v["kind"]) for d, v in _active.items() if now - _last_ins.get(d, 0) >= INSERT_EVERY]
        for d, _ in todo:
            _last_ins[d] = now
    if not todo:
        return
    try:
        for d, kind in todo:
            _insert_telemetry(db, d, kind)
        db.commit()
    except Exception:
        db.rollback()                                 # 장비가 삭제된 경우 등
        with _lock:
            for d, _ in todo:
                _active.pop(d, None)


class InjectReq(BaseModel):
    device_id: int
    kind: str


class DeviceReq(BaseModel):
    device_id: int


class ResetReq(BaseModel):
    device_id: Optional[int] = None


class DeviceInjectReq(BaseModel):
    kind: str


class RejectReq(BaseModel):
    client_uuid: str = Field(min_length=8, max_length=80)


def _device(db, device_id: int):
    dev = db.execute(text("SELECT id, name FROM devices WHERE id=:i"), {"i": device_id}).first()
    if not dev:
        raise HTTPException(status_code=404, detail="장비를 찾을 수 없습니다")
    return dev


def _resolve_incidents(db, device_id: int) -> None:
    db.execute(text("UPDATE ai_incidents SET status='resolved' "
                    "WHERE device_id=:d AND status IN ('open','block_pending')"), {"d": device_id})


def _drop_sim_rows(db, device_id: int, info) -> None:
    """시뮬레이션 구간의 합성 텔레메트리를 지워 AI 학습 기준선에 섞이지 않게 한다."""
    if info:
        db.execute(text("DELETE FROM telemetry WHERE device_id=:d AND `timestamp` >= :t"),
                   {"d": device_id, "t": info["started"]})


def _need_blocks(db) -> None:
    if not _ensure_blocks(db):
        raise HTTPException(status_code=500, detail="차단 목록 테이블(device_blocks)을 만들 수 없습니다. DB 권한을 확인하세요")


def _start_sim(db, dev, kind: str, clear_block: bool) -> dict:
    """장애 시작 공용 로직: 합성 텔레메트리 + AI 경보 + 보안 로그."""
    p = PROFILES[kind]
    if _ensure_blocks(db) and clear_block:
        db.execute(text("DELETE FROM device_blocks WHERE device_id=:d"), {"d": dev.id})   # 새 시나리오는 차단 해제 상태로 시작
    started = db.execute(text("SELECT NOW(3)")).scalar()

    row = _insert_telemetry(db, dev.id, kind)
    _resolve_incidents(db, dev.id)
    risk = round(random.uniform(90, 98), 1)
    msg = (f"{dev.name}: {p['label']} 감지 · CPU {row['cpu_usage']}% · "
           f"트래픽 {row['traffic_in_mbps']}Mbps · 손실 {row['packet_loss']}%")[:250]
    db.execute(
        text("INSERT INTO ai_incidents (device_id, risk_score, message, features) VALUES (:d,:r,:m,:f)"),
        {"d": dev.id, "r": risk, "m": msg, "f": json.dumps(to_features(row))})
    add_alert(db, "crit", f"🤖 AI 이상 감지 — {p['label']}", msg,
              f"{p['cause']} (위험도 {risk}%)", p["action"])
    db.commit()

    with _lock:
        _active[dev.id] = {"kind": kind, "until": time.time() + SIM_TTL, "started": started,
                           "name": dev.name, "mitigated": False}
        _last_ins[dev.id] = time.time()
    return {"ok": True, "device_id": dev.id, "kind": kind, "ttl": SIM_TTL,
            "recommend": p["recommend"], "reason": p["reason"]}


def build_sim_router(get_db, get_current_user, require_admin) -> APIRouter:
    r = APIRouter()

    @r.post("/api/sim/inject")
    def inject(req: InjectReq, db=Depends(get_db), user=Depends(require_admin)):
        if req.kind not in PROFILES or req.kind == "mitigated":
            raise HTTPException(status_code=400, detail="알 수 없는 시뮬레이션 종류입니다")
        dev = _device(db, req.device_id)
        return _start_sim(db, dev, req.kind, clear_block=True)

    @r.post("/api/sim/device-inject")
    def device_inject(req: DeviceInjectReq, db=Depends(get_db), x_device_id: str = Header(default="")):
        """등록된 기기(폰·아이패드)가 로그인 없이 '자기 자신'에게만 장애를 일으킨다.
        이후 완화·차단 결정은 관리자만 할 수 있고, 기기는 알림만 받는다."""
        cid = x_device_id.strip()
        if not (8 <= len(cid) <= 80):
            raise HTTPException(status_code=401, detail="기기 식별 정보가 없어요")
        if req.kind not in PROFILES or req.kind == "mitigated":
            raise HTTPException(status_code=400, detail="알 수 없는 시뮬레이션 종류입니다")
        dev = db.execute(text("SELECT id, name FROM devices WHERE client_uuid=:c"), {"c": cid}).first()
        if not dev:
            raise HTTPException(status_code=403, detail="등록된 기기만 사용할 수 있어요")
        if _ensure_blocks(db) and db.execute(text("SELECT 1 FROM device_blocks WHERE device_id=:d"),
                                             {"d": dev.id}).first():
            raise HTTPException(status_code=403, detail="연결이 차단된 상태에서는 사용할 수 없어요")
        now = time.time()
        with _lock:
            cur = _active.get(dev.id)
            if cur and cur["until"] > now:
                raise HTTPException(status_code=409, detail="이미 장애가 진행 중이에요. 관리자 조치를 기다려 주세요")
            if len(_active) >= MAX_ACTIVE:
                raise HTTPException(status_code=429, detail="지금은 시뮬레이션이 너무 많아요. 잠시 후 다시 시도해 주세요")
            if now - _dev_cd.get(dev.id, 0) < DEVICE_COOLDOWN:
                raise HTTPException(status_code=429, detail="잠시 후 다시 눌러 주세요")
            _dev_cd[dev.id] = now
        _start_sim(db, dev, req.kind, clear_block=False)
        return {"ok": True}

    @r.post("/api/sim/reject-request")
    def reject_request(req: RejectReq, db=Depends(get_db), user=Depends(require_admin)):
        """등록 요청 거절: 대기 목록에서 지우고, 요청한 기기에는 '거절됨'으로 안내한다."""
        cid = req.client_uuid.strip()
        item = _pending.pop(cid, None)
        if item is None:
            raise HTTPException(status_code=404, detail="대기 중인 요청이 없습니다")
        _rejected[cid] = time.time()
        add_alert(db, "info", "등록 요청 거절", f"{item.get('hostname') or '이름 없는 기기'} ({item.get('ip', '')}) 등록 요청을 거절했어요",
                  "관리자가 거절", "필요하면 기기에서 다시 요청할 수 있어요.")
        db.commit()
        return {"ok": True}

    @r.post("/api/sim/mitigate")
    def mitigate(req: DeviceReq, db=Depends(get_db), user=Depends(require_admin)):
        """위험도 완화: 트래픽 제한·모니터링 강화를 적용한 것으로 보고 수치를 정상 범위로 되돌린다."""
        dev = _device(db, req.device_id)
        with _lock:
            info = _active.get(dev.id)
            if not info:
                raise HTTPException(status_code=409, detail="진행 중인 시뮬레이션이 없습니다")
            info["kind"] = "mitigated"
            info["mitigated"] = True
            info["until"] = time.time() + SIM_TTL
            _last_ins[dev.id] = time.time()
        _insert_telemetry(db, dev.id, "mitigated")
        _resolve_incidents(db, dev.id)
        add_alert(db, "info", f"🛡️ 위험도 완화 — {dev.name}",
                  "관리자가 트래픽 제한(Rate limit)과 모니터링 강화를 적용했어요",
                  "이상 트래픽이 줄어 위험도가 내려갔어요", "추이를 지켜보고 재발하면 연결 차단을 검토하세요.")
        db.commit()
        return {"ok": True}

    @r.post("/api/sim/block")
    def block(req: DeviceReq, db=Depends(get_db), user=Depends(require_admin)):
        """연결 차단: 이 장비의 송수신을 차단 상태로 격리한다 (논리적 차단)."""
        dev = _device(db, req.device_id)
        _need_blocks(db)
        with _lock:
            info = _active.pop(dev.id, None)
        reason = PROFILES[info["kind"]]["label"] if info else "관리자 조치"
        _drop_sim_rows(db, dev.id, info)
        _resolve_incidents(db, dev.id)
        db.execute(text("INSERT INTO device_blocks (device_id, reason) VALUES (:d,:r) "
                        "ON DUPLICATE KEY UPDATE reason=:r, blocked_at=CURRENT_TIMESTAMP"),
                   {"d": dev.id, "r": reason[:190]})
        add_alert(db, "warn", f"🚫 연결 차단 — {dev.name}",
                  f"{dev.name}의 송수신을 차단했어요 (사유: {reason})",
                  "위험도가 높아 확산을 막기 위해 격리했어요", "원인을 점검·조치한 뒤 차단을 해제하세요.")
        db.commit()
        return {"ok": True}

    @r.post("/api/sim/unblock")
    def unblock(req: DeviceReq, db=Depends(get_db), user=Depends(require_admin)):
        """조치 완료: 차단을 해제하고 정상 상태로 복구한다."""
        dev = _device(db, req.device_id)
        _need_blocks(db)
        with _lock:
            info = _active.pop(dev.id, None)
        _drop_sim_rows(db, dev.id, info)
        _resolve_incidents(db, dev.id)
        db.execute(text("DELETE FROM device_blocks WHERE device_id=:d"), {"d": dev.id})
        add_alert(db, "info", f"✅ 조치 완료 — {dev.name}", f"{dev.name}의 차단을 해제하고 정상 모니터링으로 복구했어요",
                  "점검과 조치가 끝났어요", "정상 트래픽 패턴을 계속 모니터링하세요.")
        db.commit()
        return {"ok": True}

    @r.post("/api/sim/reset")
    def reset(req: ResetReq = ResetReq(), db=Depends(get_db), user=Depends(require_admin)):
        ready = _ensure_blocks(db)
        with _lock:
            ids = [req.device_id] if req.device_id else list(_active)
            infos = {d: _active.pop(d, None) for d in ids}
        for d, info in infos.items():
            _resolve_incidents(db, d)
            _drop_sim_rows(db, d, info)
        if ready and req.device_id:
            db.execute(text("DELETE FROM device_blocks WHERE device_id=:d"), {"d": req.device_id})
        elif ready:
            db.execute(text("DELETE FROM device_blocks"))
        add_alert(db, "info", "데이터 리셋", "시뮬레이션을 종료하고 정상 모니터링 상태로 복구했습니다.",
                  "관리자가 시뮬레이션을 해제했어요", "정상 트래픽 패턴을 계속 모니터링하세요.")
        db.commit()
        return {"ok": True, "cleared": list(infos)}

    @r.get("/api/sim/status")
    def status(db=Depends(get_db), user=Depends(get_current_user)):
        _ensure_blocks(db)
        ready = _ensure_blocks(db)
        ids = visible_device_ids(db, user)   # None = 관리자(전체)
        now = time.time()
        with _lock:
            items = [{"device_id": d, "name": v["name"], "kind": v["kind"], "label": PROFILES[v["kind"]]["label"],
                      "mitigated": bool(v.get("mitigated")), "recommend": PROFILES[v["kind"]]["recommend"],
                      "reason": PROFILES[v["kind"]]["reason"], "remaining": int(v["until"] - now)}
                     for d, v in _active.items() if v["until"] > now and (ids is None or d in ids)]
        rows = db.execute(text("SELECT b.device_id, d.name, b.reason FROM device_blocks b "
                               "JOIN devices d ON d.id=b.device_id")).fetchall() if ready else []
        blocked = [{"device_id": x.device_id, "name": x.name, "reason": x.reason}
                   for x in rows if ids is None or x.device_id in ids]
        return {"active": items, "blocked": blocked}

    @r.get("/api/sim/my-status")
    def my_status(db=Depends(get_db), x_device_id: str = Header(default="")):
        """로그인 없이 쓰는 기기(폰·아이패드)가 자기 상태를 확인한다. 기기 식별은 X-Device-Id."""
        cid = x_device_id.strip()
        if not (8 <= len(cid) <= 80):
            return {"state": "none"}
        ready = _ensure_blocks(db)
        dev = db.execute(text("SELECT id, name FROM devices WHERE client_uuid=:c"), {"c": cid}).first()
        if not dev:
            if cid in _pending:
                return {"state": "pending"}
            if time.time() - _rejected.get(cid, 0) < REJECT_TTL:
                return {"state": "rejected"}
            _rejected.pop(cid, None)
            return {"state": "none"}
        if ready and db.execute(text("SELECT 1 FROM device_blocks WHERE device_id=:d"), {"d": dev.id}).first():
            return {"state": "blocked", "name": dev.name}
        with _lock:
            info = _active.get(dev.id)
            live = info and info["until"] > time.time()
            kind, mitigated = (info["kind"], bool(info.get("mitigated"))) if live else (None, False)
        if live:
            return {"state": "mitigated" if mitigated else "warning", "name": dev.name,
                    "label": PROFILES[kind]["label"]}
        return {"state": "normal", "name": dev.name}

    return r
