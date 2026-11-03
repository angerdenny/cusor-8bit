"""실제 환경 장애 시뮬레이션 (전시용)

관리자가 대시보드에서 '대상 장비'(예: 테스트 아이패드)를 고르고 장애 버튼을 누르면
- 그 장비에 합성 텔레메트리(CPU/메모리/트래픽/손실)를 주기적으로 넣고
- AI 경보(ai_incidents)와 보안 로그(alerts)를 만든다.
화면의 노드 색, AI 위험 스코어, 경보 팝업은 기존 실제 환경 파이프라인이 그대로 처리한다.

- POST /api/sim/inject   {device_id, kind}   관리자 전용
- POST /api/sim/reset    {device_id?}        관리자 전용 (생략하면 전체 해제)
- GET  /api/sim/status                       로그인 사용자 (본인에게 보이는 장비만)

위치: src/backend/sim_routes.py
"""
import json
import random
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from .ai_routes import add_alert, to_features, visible_device_ids

SIM_TTL = 600        # 시뮬레이션 자동 종료 시간(초)
INSERT_EVERY = 4     # 장비당 합성 텔레메트리 최소 간격(초)

PROFILES = {
    "ddos": {
        "label": "DDoS 부하", "cpu": (85, 97), "ram": (70, 85), "traffic": (900, 1400), "loss": (3, 8),
        "cause": "외부에서 다량의 위조 트래픽이 집중되어 대역폭과 세션 자원이 고갈되는 상황이에요.",
        "action": "의심 IP 대역을 차단하고 ISP에 트래픽 정화를 요청하세요.",
    },
    "loss": {
        "label": "패킷 손실", "cpu": (30, 45), "ram": (40, 55), "traffic": (80, 160), "loss": (18, 35),
        "cause": "회선 품질 저하나 큐 오버플로우로 패킷이 유실되고 있어요.",
        "action": "회선·케이블 상태를 점검하고 QoS 큐 설정을 조정하세요.",
    },
    "cpu": {
        "label": "CPU 고부하", "cpu": (96, 100), "ram": (80, 92), "traffic": (100, 200), "loss": (0, 2),
        "cause": "대량 연결 처리로 CPU 점유율이 임계치를 넘어 과부하 상태예요.",
        "action": "불필요한 프로세스와 세션을 정리하고 이중화 경로로 전환하세요.",
    },
    "down": {
        "label": "회선 다운", "cpu": (3, 8), "ram": (30, 38), "traffic": (0, 1), "loss": (100, 100),
        "cause": "케이블 단선이나 포트 장애로 회선 연결이 끊어졌어요.",
        "action": "현장 케이블·포트를 확인하고 예비 회선으로 절체하세요.",
    },
}

_active: dict = {}   # device_id -> {kind, until, started, name}
_last_ins: dict = {}
_lock = threading.Lock()


def _sample(kind: str) -> dict:
    p = PROFILES[kind]
    u = random.uniform
    return {
        "cpu_usage": round(u(*p["cpu"]), 1),
        "ram_usage": round(u(*p["ram"]), 1),
        "traffic_in_mbps": round(u(*p["traffic"]), 1),
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


class ResetReq(BaseModel):
    device_id: Optional[int] = None


def build_sim_router(get_db, get_current_user, require_admin) -> APIRouter:
    r = APIRouter()

    @r.post("/api/sim/inject")
    def inject(req: InjectReq, db=Depends(get_db), user=Depends(require_admin)):
        if req.kind not in PROFILES:
            raise HTTPException(status_code=400, detail="알 수 없는 시뮬레이션 종류입니다")
        dev = db.execute(text("SELECT id, name FROM devices WHERE id=:i"), {"i": req.device_id}).first()
        if not dev:
            raise HTTPException(status_code=404, detail="장비를 찾을 수 없습니다")
        p = PROFILES[req.kind]
        started = db.execute(text("SELECT NOW(3)")).scalar()

        row = _insert_telemetry(db, dev.id, req.kind)
        # 같은 장비의 이전 열린 경보는 닫고 새 경보를 만든다
        db.execute(text("UPDATE ai_incidents SET status='resolved' "
                        "WHERE device_id=:d AND status IN ('open','block_pending')"), {"d": dev.id})
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
            _active[dev.id] = {"kind": req.kind, "until": time.time() + SIM_TTL,
                               "started": started, "name": dev.name}
            _last_ins[dev.id] = time.time()
        return {"ok": True, "device_id": dev.id, "kind": req.kind, "ttl": SIM_TTL}

    @r.post("/api/sim/reset")
    def reset(req: ResetReq = ResetReq(), db=Depends(get_db), user=Depends(require_admin)):
        with _lock:
            ids = [req.device_id] if req.device_id else list(_active)
            infos = {d: _active.pop(d, None) for d in ids}
        for d, info in infos.items():
            db.execute(text("UPDATE ai_incidents SET status='resolved' "
                            "WHERE device_id=:d AND status IN ('open','block_pending')"), {"d": d})
            if info:   # 합성 텔레메트리가 AI 학습 기준선에 섞이지 않도록 시뮬레이션 구간 데이터 삭제
                db.execute(text("DELETE FROM telemetry WHERE device_id=:d AND `timestamp` >= :t"),
                           {"d": d, "t": info["started"]})
        add_alert(db, "info", "데이터 리셋", "시뮬레이션을 종료하고 정상 모니터링 상태로 복구했습니다.",
                  "관리자가 시뮬레이션을 해제했어요", "정상 트래픽 패턴을 계속 모니터링하세요.")
        db.commit()
        return {"ok": True, "cleared": list(infos)}

    @r.get("/api/sim/status")
    def status(db=Depends(get_db), user=Depends(get_current_user)):
        ids = visible_device_ids(db, user)   # None = 관리자(전체)
        now = time.time()
        with _lock:
            items = [{"device_id": d, "name": v["name"], "kind": v["kind"],
                      "label": PROFILES[v["kind"]]["label"], "remaining": int(v["until"] - now)}
                     for d, v in _active.items() if v["until"] > now and (ids is None or d in ids)]
        return {"active": items}

    return r
