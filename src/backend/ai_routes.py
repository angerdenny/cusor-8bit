"""AI 위험도 / 관리자 승인 차단 / 오탐 피드백 / 미등록 기기 감지."""
import os
import re
import hmac
import ipaddress
import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

sys.path.append(str(Path(__file__).resolve().parents[1]))  # src/ 를 import 경로에 추가
from ai.detector import detector  # noqa: E402

# telemetry 실제 컬럼: cpu_usage, ram_usage, traffic_in_mbps, packet_loss (ping 없음 → 항상 0)
CANDIDATES = {
    "cpu": ("cpu_usage", "cpu"),
    "ram": ("ram_usage", "ram"),
    "traffic": ("traffic_in_mbps", "traffic_in", "traffic"),
    "ping": ("ping", "latency", "latency_ms"),
    "loss": ("packet_loss", "loss"),
}
TRAIN_SQL = "SELECT * FROM telemetry WHERE device_id = 85 ORDER BY id DESC LIMIT 5000"
SUSPECT_TTL = 60  # 초. 이보다 오래된 의심 프로세스 보고는 무시

_lock = threading.Lock()
_commands: dict[int, list[dict]] = {}  # device_id -> 대기 중 명령 (서버 재시작 시 초기화)
_suspects: dict[int, dict] = {}        # device_id -> 에이전트가 보고한 의심 프로세스
_pending: dict[str, dict] = {}         # ip -> 미등록 기기
_conn_reqs: dict[int, dict] = {}   # 승인자(기기) device_id -> 연결 요청
_conn_done: list[dict] = []        # 관리자에게 알릴 처리 결과

class ConnReq(BaseModel):
    source_id: int
    target_id: int


class ConnResp(BaseModel):
    request_id: str
    accept: bool


ALLOWED_TYPES = {"router", "switch", "server", "app", "pc", "mobile", "firewall", "printer", "access-point"}
_last_req: dict[str, float] = {}


def _clean_name(s: str) -> str:
    """팝업 HTML에 들어가므로 위험 문자를 제거한다."""
    return re.sub(r'[<>"\'&`\\]', "", s or "").strip()[:50]


class SelfRegisterReq(BaseModel):
    name: str
    type: str = "mobile"

def _pick(row: dict, names: tuple) -> float:
    for n in names:
        if row.get(n) is not None:
            try:
                return float(row[n])
            except (TypeError, ValueError):
                pass
    return 0.0


def to_features(row: dict) -> dict:
    return {k: _pick(row, v) for k, v in CANDIDATES.items()}


def _json(v):
    return json.loads(v) if isinstance(v, (str, bytes)) else (v or {})

def add_alert(db, lv, title, msg, cause="", action=""):
    """보안 로그(alerts)에 한 줄 남긴다. commit은 호출한 쪽에서 한다."""
    db.execute(text("INSERT INTO alerts (lv, title, msg, cause, action) VALUES (:lv,:t,:m,:c,:a)"),
               {"lv": lv, "t": title[:190], "m": msg, "c": cause[:490], "a": action[:490]})


class BlockReq(BaseModel):
    incident_id: int
    mode: Literal["kill", "firewall"] = "kill"


class FeedbackReq(BaseModel):
    incident_id: int


class HelloReq(BaseModel):
    ip: str
    hostname: str = ""


class SuspectReq(BaseModel):
    device_id: int
    pid: int
    name: str
    create_time: float
    exe: str = ""


class CmdResult(BaseModel):
    ok: bool
    detail: str = ""


class EnrollReq(BaseModel):
    ip: str
    name: str
    type: str = "pc"
    vlan_code: str


def score_rows(db, rows: list[dict]) -> list[dict]:
    """telemetry 행들에 risk_score를 붙이고, 이상이면 경보(ai_incidents)와 보안 로그(alerts)를 만든다.
    main.py의 /api/telemetry/latest 에서 호출."""
    if not detector.trained:
        train = [to_features(dict(x._mapping)) for x in db.execute(text(TRAIN_SQL))]
        if len(train) >= 50:
            detector.train_baseline(train)

    seen = set()  # rows는 id DESC 이므로 장비별 첫 행이 최신
    for row in rows:
        feats = to_features(row)
        res = detector.predict_risk(feats)
        row["risk_score"], row["is_anomaly"] = res["risk_score"], res["is_anomaly"]
        dev = row.get("device_id")
        if dev is None or dev in seen:
            continue
        seen.add(dev)
        if not (detector.trained and res["is_anomaly"]):
            continue  # 미학습 상태에서는 경보를 만들지 않는다
        if db.execute(text("SELECT 1 FROM ai_incidents WHERE device_id=:d AND status IN ('open','block_pending') LIMIT 1"),
                      {"d": dev}).first():
            continue  # 이미 열린 경보가 있으면 새로 만들지 않는다 (중복·도배 방지)
        s = _suspects.get(dev)
        if s and time.time() - s["ts"] > SUSPECT_TTL:
            s = None
        msg = (f"의심 프로세스 {s['name']}(PID {s['pid']}) 감지! 차단하시겠습니까?" if s
               else f"장비 #{dev}: {res['top_factor'] or '이상'} 이상 징후 감지")
        db.execute(text(
            "INSERT INTO ai_incidents (device_id, risk_score, message, process_name, pid, proc_create_time, features) "
            "VALUES (:d,:r,:m,:pn,:pid,:ct,:f)"),
            {"d": dev, "r": res["risk_score"], "m": msg, "pn": s and s["name"], "pid": s and s["pid"],
             "ct": s and s["create_time"], "f": json.dumps(feats)})
        add_alert(db, "crit", "🤖 AI 이상 감지", msg,
                  f"위험도 {res['risk_score']}% · 주요 요인: {res['top_factor'] or '-'}",
                  "승인/차단 또는 오탐/재학습을 선택하세요")
        db.commit()
    return rows
            
               


def build_ai_router(get_db, get_current_user, require_admin, agent_key: str) -> APIRouter:
    r = APIRouter()

    def agent_auth(x_api_key: str = Header(default="")):
        if not x_api_key or not hmac.compare_digest(x_api_key, agent_key):
            raise HTTPException(status_code=403, detail="Invalid API Key")

    # ---------- 경보 조회 / 재학습 ----------
    @r.get("/api/ai/incidents")
    def incidents(db=Depends(get_db), user=Depends(get_current_user)):
        rows = db.execute(text(
            "SELECT id, device_id, risk_score, message, status, process_name, pid, created_at "
            "FROM ai_incidents WHERE status IN ('open','block_pending') ORDER BY id DESC LIMIT 20")).fetchall()
        return {"can_act": user.get("role") == "admin", "incidents": [dict(x._mapping) for x in rows],
                "model_trained": detector.trained}

    @r.post("/api/ai/train")
    def retrain(db=Depends(get_db), user=Depends(require_admin)):
        rows = [to_features(dict(x._mapping)) for x in db.execute(text(TRAIN_SQL))]
        try:
            return {"trained_samples": detector.train_baseline(rows)}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ---------- 관리자 승인 차단 ----------
    @r.post("/api/security/block")
    def approve_block(req: BlockReq, db=Depends(get_db), user=Depends(require_admin)):
        a = db.execute(text("SELECT * FROM ai_incidents WHERE id=:i"), {"i": req.incident_id}).first()
        if not a:
            raise HTTPException(status_code=404, detail="경보를 찾을 수 없습니다")
        a = dict(a._mapping)
        if a["status"] != "open":
            raise HTTPException(status_code=409, detail="이미 처리된 경보입니다")
        if not a["pid"]:
            raise HTTPException(status_code=400, detail="차단할 프로세스 정보가 없습니다")
        cmd = {"id": uuid.uuid4().hex, "incident_id": a["id"], "mode": req.mode,
               "pid": a["pid"], "name": a["process_name"], "create_time": a["proc_create_time"]}
        with _lock:
            _commands.setdefault(a["device_id"], []).append(cmd)
        db.execute(text("UPDATE ai_incidents SET status='block_pending' WHERE id=:i"), {"i": a["id"]})
        add_alert(db, "warn", "🛡 차단 승인", f"관리자가 '{a['process_name']}'(PID {a['pid']}) 차단을 승인했습니다",
                  "관리자 승인", "에이전트가 프로세스를 종료합니다")
        db.commit()
        return {"command_id": cmd["id"], "status": "block_pending"}

    # ---------- 오탐 피드백 (재학습) ----------
    @r.post("/api/ai/feedback")
    def feedback(req: FeedbackReq, db=Depends(get_db), user=Depends(require_admin)):
        a = db.execute(text("SELECT features FROM ai_incidents WHERE id=:i"), {"i": req.incident_id}).first()
        if not a or not a.features:
            raise HTTPException(status_code=404, detail="경보 또는 특징 데이터가 없습니다")
        feats = _json(a.features)
        before = detector.predict_risk(feats)["risk_score"]
        try:
            total = detector.add_feedback(feats)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        after = detector.predict_risk(feats)["risk_score"]
        add_alert(db, "info", "♻ 오탐 재학습", f"위험도 {before}% → {after}%", "관리자가 오탐으로 판정", "정상 기준선에 반영됨")
        db.execute(text("UPDATE ai_incidents SET status='false_positive' WHERE id=:i"), {"i": req.incident_id})
        db.commit()
        return {"risk_before": before, "risk_after": detector.predict_risk(feats)["risk_score"], "baseline_size": total}

    # ---------- 에이전트 전용 ----------
    @r.post("/api/agent/hello", dependencies=[Depends(agent_auth)])
    def hello(req: HelloReq, db=Depends(get_db)):
        row = db.execute(text("SELECT id FROM devices WHERE ip=:ip"), {"ip": req.ip}).first()
        if row:
            _pending.pop(req.ip, None)
            return {"registered": True, "device_id": row.id}
        cur = _pending.get(req.ip)
        if not (cur and cur.get("requested")):  # 사용자가 직접 입력한 이름을 스캐너가 덮어쓰지 않게
            _pending[req.ip] = {"ip": req.ip, "hostname": _clean_name(req.hostname)}
        return {"registered": False}

    @r.post("/api/agent/suspect", dependencies=[Depends(agent_auth)])
    def suspect(req: SuspectReq):
        _suspects[req.device_id] = {**req.model_dump(), "ts": time.time()}
        return {"ok": True}

    @r.get("/api/agent/commands", dependencies=[Depends(agent_auth)])
    def poll_commands(device_id: int):
        with _lock:
            return {"commands": _commands.pop(device_id, [])}

    @r.post("/api/agent/commands/{cmd_id}/result", dependencies=[Depends(agent_auth)])
    def cmd_result(cmd_id: str, res: CmdResult, incident_id: int, db=Depends(get_db)):
        status = "blocked" if res.ok else "block_failed"
        db.execute(text("UPDATE ai_incidents SET status=:s WHERE id=:i"), {"s": status, "i": incident_id})
        add_alert(db, "info" if res.ok else "crit", "차단 완료" if res.ok else "차단 실패", res.detail, "에이전트 실행 결과")
        db.commit()
        return {"status": status, "detail": res.detail}

    # ---------- 미등록 기기 등록 (기존 /api/devices/pending, /enroll 은 건드리지 않음) ----------
    @r.get("/api/ai/pending-devices")
    def pending(user=Depends(require_admin)):
        return list(_pending.values())

    @r.post("/api/ai/enroll")
    def enroll(req: EnrollReq, db=Depends(get_db), user=Depends(require_admin)):
        allowed = {"router", "switch", "server", "app", "pc", "mobile", "firewall", "printer", "access-point"}
        if req.type not in allowed:
            raise HTTPException(status_code=400, detail="허용되지 않은 기기 종류입니다")
        try:
            ip = str(ipaddress.ip_address(req.ip.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="IP 형식이 올바르지 않습니다")
        if not req.name.strip():
            raise HTTPException(status_code=400, detail="장비 이름을 입력해 주세요")
        vlan = db.execute(text("SELECT id FROM vlans WHERE code=:c"), {"c": req.vlan_code}).first()
        if not vlan:
            raise HTTPException(status_code=400, detail="Unknown vlan_code")
        try:
            db.execute(text("INSERT INTO devices (name, ip, type, owner_id, x, y, vlan_id) "
                            "VALUES (:n,:ip,:t,:o,50,50,:v)"),
                       {"n": req.name.strip(), "ip": ip, "t": req.type, "o": user["user_id"], "v": vlan[0]})
            add_alert(db, "info", "기기 등록", f"{req.name.strip()} ({ip}) 등록", "관리자 승인")
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=400, detail="이미 등록되었거나 장비 정보가 올바르지 않습니다")
        _pending.pop(ip, None)
        return {"ok": True}
    
    # ---------- 기기 본인 화면용 (로그인 없이 접근, 접속한 IP를 서버가 직접 확인) ----------
    @r.get("/api/ai/whoami")
    def whoami(request: Request, db=Depends(get_db)):
        ip = request.client.host if request.client else ""
        if ip in ("127.0.0.1", "::1"):  # 서버 PC 자신은 건너뜀
            return {"ip": ip, "local": True, "registered": True}
        row = db.execute(text("SELECT id, name FROM devices WHERE ip=:ip"), {"ip": ip}).first()
        return {"ip": ip, "registered": bool(row), "name": row.name if row else None}

    @r.post("/api/ai/register-request")
    def register_request(req: SelfRegisterReq, request: Request, db=Depends(get_db)):
        ip = request.client.host if request.client else ""
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise HTTPException(status_code=400, detail="접속 IP를 확인할 수 없습니다")
        if time.time() - _last_req.get(ip, 0) < 5:
            raise HTTPException(status_code=429, detail="잠시 후 다시 시도해 주세요")
        _last_req[ip] = time.time()
        name = _clean_name(req.name)
        if not name:
            raise HTTPException(status_code=400, detail="기기 이름을 입력해 주세요")
        if req.type not in ALLOWED_TYPES:
            raise HTTPException(status_code=400, detail="허용되지 않은 기기 종류입니다")
        if db.execute(text("SELECT 1 FROM devices WHERE ip=:ip"), {"ip": ip}).first():
            return {"registered": True}

        auto = os.getenv("AUTO_ENROLL_VLAN", "").strip()  # 시연용: 승인 없이 이 구역에 바로 등록
        if auto:
            vlan = db.execute(text("SELECT id FROM vlans WHERE code=:c"), {"c": auto}).first()
            admin = db.execute(text("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")).first()
            if not vlan or not admin:
                raise HTTPException(status_code=500, detail="자동 등록 설정(구역 또는 관리자)을 확인해 주세요")
            try:
                db.execute(text("INSERT INTO devices (name, ip, type, owner_id, x, y, vlan_id) "
                                "VALUES (:n,:ip,:t,:o,50,50,:v)"),
                           {"n": name, "ip": ip, "t": req.type, "o": admin[0], "v": vlan[0]})
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=400, detail="등록할 수 없습니다")
            _pending.pop(ip, None)
            return {"registered": True}

        if len(_pending) >= 100 and ip not in _pending:
            raise HTTPException(status_code=429, detail="대기 중인 요청이 너무 많습니다")
        _pending[ip] = {"ip": ip, "hostname": name, "type": req.type, "requested": True}
        return {"registered": False}
    
    # ---------- 연결 요청 (관리자 → 기기 승인) ----------
    def _me(db, request: Request):
        ip = request.client.host if request.client else ""
        return db.execute(text("SELECT id, name FROM devices WHERE ip=:ip"), {"ip": ip}).first()

    def _linked(db, a, b):
        return db.execute(text("SELECT 1 FROM links WHERE (source_id=:a AND target_id=:b) "
                               "OR (source_id=:b AND target_id=:a)"), {"a": a, "b": b}).first()

    @r.post("/api/ai/connect-request")
    def connect_request(req: ConnReq, db=Depends(get_db), user=Depends(require_admin)):
        if req.source_id == req.target_id:
            raise HTTPException(status_code=400, detail="같은 장비끼리는 연결할 수 없습니다")
        rows = {x.id: x for x in db.execute(
            text("SELECT id, name, type FROM devices WHERE id IN (:a,:b)"),
            {"a": req.source_id, "b": req.target_id})}
        if len(rows) != 2:
            raise HTTPException(status_code=404, detail="Device not found")
        if _linked(db, req.source_id, req.target_id):
            raise HTTPException(status_code=400, detail="이미 연결되어 있는 장비입니다")
        # 승인하는 쪽: mobile 기기 (없으면 대상 기기)
        appr, other = ((req.source_id, req.target_id) if rows[req.source_id].type == "mobile" and rows[req.target_id].type != "mobile"
                       else (req.target_id, req.source_id))
        _conn_reqs[appr] = {"id": uuid.uuid4().hex, "other": other, "appr": appr,
                            "from_name": rows[other].name, "ts": time.time()}
        return {"ok": True}

    @r.get("/api/ai/my-connect-request")
    def my_connect_request(request: Request, db=Depends(get_db)):
        me = _me(db, request)
        q = _conn_reqs.get(me.id) if me else None
        if q and time.time() - q["ts"] > 120:   # 2분 지나면 만료
            _conn_reqs.pop(me.id, None)
            q = None
        return {"request": {"id": q["id"], "from_name": q["from_name"]} if q else None}

    @r.post("/api/ai/connect-respond")
    def connect_respond(res: ConnResp, request: Request, db=Depends(get_db)):
        me = _me(db, request)
        q = _conn_reqs.get(me.id) if me else None
        if not q or q["id"] != res.request_id:
            raise HTTPException(status_code=404, detail="처리할 연결 요청이 없습니다")
        _conn_reqs.pop(me.id, None)
        if res.accept and not _linked(db, q["other"], q["appr"]):
            try:
                db.execute(text("INSERT INTO links (source_id, target_id) VALUES (:a,:b)"),
                           {"a": q["other"], "b": q["appr"]})
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=400, detail="연결 정보가 올바르지 않습니다")
        _conn_done.append({"accepted": res.accept, "a": q["from_name"], "b": me.name})
        return {"ok": True}

    @r.get("/api/ai/connect-results")
    def connect_results(user=Depends(require_admin)):
        out = list(_conn_done)
        _conn_done.clear()
        return {"results": out}

    # ---------- 연결 상태 (에이전트 없는 기기: 핑 기반) ----------
    @r.get("/api/ai/connectivity")
    def connectivity(db=Depends(get_db), user=Depends(get_current_user)):
        agent = {x[0] for x in db.execute(text(
            "SELECT DISTINCT device_id FROM telemetry WHERE timestamp > NOW() - INTERVAL 30 SECOND"))}
        rows = db.execute(text("""
            SELECT device_id, ok, rtt_ms FROM (
              SELECT device_id, ok, rtt_ms,
                     ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY id DESC) AS rn
              FROM ping_logs WHERE created_at > NOW() - INTERVAL 2 MINUTE) t
            WHERE rn <= 10 ORDER BY device_id, rn""")).fetchall()
        by: dict[int, list] = {}
        for x in rows:
            by.setdefault(x.device_id, []).append(x)
        out = {}
        for dev, lst in by.items():
            if dev in agent:
                continue
            lead = 0                       # 최근부터 연속 실패 횟수
            for x in lst:
                if x.ok:
                    break
                lead += 1
            loss = round(100 * sum(1 for x in lst if not x.ok) / len(lst))
            rtts = [x.rtt_ms for x in lst if x.ok and x.rtt_ms is not None]
            avg = sum(rtts) / len(rtts) if rtts else None
            if lead >= 3:
                status = "offline"
            elif loss >= 20:
                status = "unstable"
            elif avg is not None and avg >= 150:
                status = "slow"
            else:
                status = "online"
            out[dev] = {"source": "ping", "status": status, "rtt_ms": avg, "loss": loss}
        for dev in agent:
            out[dev] = {"source": "agent", "status": "online"}
        return {"devices": out}
    return r