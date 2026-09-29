import uvicorn
import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles
from fastapi import Depends, FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

# .env 파일 읽기
load_dotenv()
AGENT_API_KEY = os.getenv("AGENT_API_KEY")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET이 .env 파일에 없습니다.")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

from database import get_db
from models import Alert, AlertDevice, Device, User

app = FastAPI(title="8bit AI Pulse API")


@app.get("/api/test")
def test():
    return {"message": "ok"}

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()

    if not user or not pwd_context.verify(body.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="아이디 또는 비밀번호가 올바르지 않습니다",
        )

    payload = {
        "sub": user.username,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "role": user.role}

@app.get("/api/devices")
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.id).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "ip": d.ip,
            "type": d.type,
            "owner_id": d.owner_id,
            "x": d.x,
            "y": d.y,
            "vlan_id": d.vlan_id,
            "vlan_name": d.vlan.name,
        }
        for d in devices
    ]


@app.get("/api/telemetry/latest")
def latest_telemetry(db: Session = Depends(get_db)):
    rows = db.execute(
        text(
            """
            SELECT v.device_id, d.name, v.cpu_usage, v.ram_usage,
                   v.traffic_in_mbps, v.packet_loss, v.`timestamp`
            FROM v_latest_telemetry v
            JOIN devices d ON d.id = v.device_id
            ORDER BY v.device_id
            """
        )
    ).mappings().all()

    telemetry = [
        {
            "device_id": r["device_id"],
            "device_name": r["name"],
            "cpu_usage": r["cpu_usage"],
            "ram_usage": r["ram_usage"],
            "traffic_in_mbps": r["traffic_in_mbps"],
            "packet_loss": r["packet_loss"],
            "timestamp": r["timestamp"].isoformat(),
        }
        for r in rows
    ]

    alerts = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .limit(20)
        .all()
    )
    alert_ids = [a.id for a in alerts]
    links = db.query(AlertDevice).filter(AlertDevice.alert_id.in_(alert_ids)).all()
    devices_by_alert = {}
    for link in links:
        devices_by_alert.setdefault(link.alert_id, []).append(link.device_id)

    return {
        "telemetry": telemetry,
        "alerts": [
            {
                "id": a.id,
                "lv": a.lv,
                "title": a.title,
                "msg": a.msg,
                "cause": a.cause,
                "action": a.action,
                "timestamp": a.timestamp.isoformat(),
                "device_ids": devices_by_alert.get(a.id, []),
            }
            for a in alerts
        ],
    }
@app.get("/api/endpoint-security/events")
def endpoint_events(since: int = 0, db: Session = Depends(get_db)):
    rows = db.execute(
        text(
            """
            SELECT id, action, process_name, pid, reason, created_at
            FROM endpoint_events
            WHERE id > :since
            ORDER BY id
            LIMIT 200
            """
        ),
        {"since": since},
    ).mappings().all()

    return [
        {
            "id": r["id"],
            "action": r["action"],
            "process_name": r["process_name"],
            "pid": r["pid"],
            "reason": r["reason"],
            "time": r["created_at"].isoformat(),
        }
        for r in rows
    ]
    
class EndpointEventIn(BaseModel):
    action: str
    process_name: str
    pid: int | None = None
    reason: str = ""


@app.post("/api/endpoint-security/events", status_code=201)
def create_endpoint_event(
    event: EndpointEventIn, 
    db: Session = Depends(get_db)
):  
    if event.action not in ("block", "allow"):
        raise HTTPException(status_code=400, detail="action은 block 또는 allow여야 합니다.")
    
    result = db.execute(
        text("INSERT INTO endpoint_events (action, process_name, pid, reason) VALUES (:action, :process_name, :pid, :reason)"),
        {
            "action": event.action,
            "process_name": event.process_name,
            "pid": event.pid,
            "reason": event.reason,
        }
    )
    db.commit()
    return {"id": 1}

PUBLIC_DIR = Path(__file__).resolve().parents[2] / "public"
app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="public")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)