"""연결 상태 측정기: 등록된 기기를 핑해서 ping_logs에 기록한다. (기기에 설치할 것 없음)"""
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import text

from database import SessionLocal

INTERVAL = 5  # 초
RTT_RE = re.compile(r"[=<]\s*(\d+)\s*ms")  # 한글/영문 윈도우 모두: 시간=12ms, time<1ms


def ping(ip: str) -> tuple[bool, float | None]:
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                           capture_output=True, text=True, errors="ignore", timeout=5)
    except Exception:
        return False, None
    out = r.stdout or ""
    # "대상 호스트에 연결할 수 없음"도 종료코드 0일 수 있어서 TTL 응답까지 확인한다
    if r.returncode != 0 or "TTL=" not in out.upper():
        return False, None
    m = RTT_RE.search(out)
    return True, float(m.group(1)) if m else None


def main() -> None:
    print("[pinger] 시작: 등록된 기기를 5초마다 핑합니다")
    n = 0
    while True:
        try:
            with SessionLocal() as db:
                devs = [d for d in db.execute(text("SELECT id, ip FROM devices")).fetchall() if d.ip]
                with ThreadPoolExecutor(max_workers=16) as ex:
                    results = list(ex.map(lambda d: ping(d.ip), devs))
                for d, (ok, rtt) in zip(devs, results):
                    db.execute(text("INSERT INTO ping_logs (device_id, ok, rtt_ms) VALUES (:d,:o,:r)"),
                               {"d": d.id, "o": 1 if ok else 0, "r": rtt})
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