"""연결 상태 측정기: 등록된 기기를 핑해서 ping_logs에 기록하고, 끊김/복구를 보안 로그에 남긴다."""
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import text

from database import SessionLocal

INTERVAL = 5  # 초
RTT_RE = re.compile(r"[=<]\s*(\d+)\s*ms")
fail_cnt: dict[int, int] = {}   # 기기별 연속 실패 횟수
down: set[int] = set()          # 현재 오프라인으로 알린 기기


def ping(ip: str) -> tuple[bool, float | None]:
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                           capture_output=True, text=True, errors="ignore", timeout=5)
    except Exception:
        return False, None
    out = r.stdout or ""
    if r.returncode != 0 or "TTL=" not in out.upper():
        return False, None
    m = RTT_RE.search(out)
    return True, float(m.group(1)) if m else None


def log_alert(db, lv: str, title: str, msg: str, cause: str = "", action: str = "") -> None:
    db.execute(text("INSERT INTO alerts (lv, title, msg, cause, action) VALUES (:lv,:t,:m,:c,:a)"),
               {"lv": lv, "t": title[:190], "m": msg, "c": cause, "a": action})


def main() -> None:
    print("[pinger] 시작: 등록된 기기를 5초마다 핑합니다")
    n = 0
    while True:
        try:
            with SessionLocal() as db:
                devs = [d for d in db.execute(text("SELECT id, name, ip FROM devices")).fetchall() if d.ip]
                with ThreadPoolExecutor(max_workers=16) as ex:
                    results = list(ex.map(lambda d: ping(d.ip), devs))
                for d, (ok, rtt) in zip(devs, results):
                    db.execute(text("INSERT INTO ping_logs (device_id, ok, rtt_ms) VALUES (:d,:o,:r)"),
                               {"d": d.id, "o": 1 if ok else 0, "r": rtt})
                    fail_cnt[d.id] = 0 if ok else fail_cnt.get(d.id, 0) + 1
                    if fail_cnt[d.id] == 3 and d.id not in down:        # 3회 연속 실패 = 오프라인
                        down.add(d.id)
                        log_alert(db, "crit", f"✖ {d.name} 오프라인", f"{d.name}({d.ip}) 응답이 없습니다",
                                  "핑 3회 연속 실패", "전원과 Wi-Fi 연결을 확인하세요")
                    elif ok and d.id in down:
                        down.discard(d.id)
                        log_alert(db, "info", f"● {d.name} 복구", f"{d.name}({d.ip}) 응답이 돌아왔습니다")
                n += 1
                if n % 60 == 0:  # 5분마다 1시간 지난 기록 삭제
                    db.execute(text("DELETE FROM ping_logs WHERE created_at < NOW() - INTERVAL 1 HOUR"))
                db.commit()
        except Exception as e:
            print(f"[pinger] 오류: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[pinger] 종료합니다.")