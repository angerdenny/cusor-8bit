# -*- coding: utf-8 -*-
"""PC 상태 수집기 (DB에 직접 접속하지 않고 서버 API로만 보고)

처음 실행하면
1. 이 PC 고유 ID(agent_id.txt)를 만든다.
2. 연결 코드(6자리)를 화면에 보여준다.
3. 사용자가 웹의 '내 PC 연결'에 코드를 입력하면 그 사용자 소유로 연결된다.
4. 연결된 뒤로 CPU/메모리/트래픽을 주기적으로 서버에 보낸다.
"""
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import psutil
import requests
from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

BACKEND = os.getenv("BACKEND_URL", "https://cusor-8bit.onrender.com").rstrip("/")
AGENT_KEY = os.getenv("AGENT_API_KEY")
if not AGENT_KEY:
    sys.exit("AGENT_API_KEY가 .env에 없습니다.")
HEADERS = {"X-API-Key": AGENT_KEY}

INTERVAL = int(os.getenv("COLLECT_INTERVAL_SEC", "5"))
PING_TARGET = os.getenv("PING_TARGET", "8.8.8.8")
PAIR_INTERVAL = 10  # 연결 대기 중 재확인 주기(초)
ID_FILE = HERE / "agent_id.txt"


def load_agent_id() -> str:
    """이 PC의 고유 ID. 한 번 만들면 같은 파일을 계속 쓴다 (PC 이름이 같아도 구분됨)."""
    if ID_FILE.exists():
        return ID_FILE.read_text(encoding="utf-8").strip()
    new_id = uuid.uuid4().hex
    ID_FILE.write_text(new_id, encoding="utf-8")
    return new_id


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 패킷은 보내지 않고 인터페이스만 고른다
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def measure_packet_loss() -> float:
    flag = "-n" if os.name == "nt" else "-c"
    try:
        r = subprocess.run(["ping", flag, "1", PING_TARGET], capture_output=True, timeout=3)
        return 0.0 if r.returncode == 0 else 100.0
    except (subprocess.TimeoutExpired, OSError):
        return 100.0


def api(method: str, path: str, **kwargs) -> requests.Response:
    return requests.request(method, BACKEND + path, headers=HEADERS, timeout=10, **kwargs)


def wait_for_link(agent_id: str) -> None:
    """연결될 때까지 기다린다. 연결 코드는 화면에 표시한다."""
    name = os.getenv("COLLECT_DEVICE_NAME") or socket.gethostname()
    shown = None
    while True:
        try:
            r = api("POST", "/api/agent/pair-request",
                    json={"agent_id": agent_id, "name": name, "ip": local_ip()})
            r.raise_for_status()
            data = r.json()
            if data.get("linked"):
                print(f"[collector] 연결 완료 (device_id={data['device_id']})")
                return
            if data.get("code") != shown:
                shown = data["code"]
                print("=" * 50)
                print(f"  연결 코드: {shown}")
                print("  웹사이트 로그인 → '내 PC 연결'에 이 코드를 입력하세요.")
                print(f"  (약 {data.get('expires_in', 600) // 60}분 동안 유효)")
                print("=" * 50)
        except requests.RequestException as e:
            print(f"[collector] 서버 연결 실패, 재시도: {e}")
        time.sleep(PAIR_INTERVAL)


def main() -> None:
    agent_id = load_agent_id()
    print(f"[collector] PC ID: {agent_id[:8]}... / 서버: {BACKEND}")

    wait_for_link(agent_id)

    psutil.cpu_percent(interval=None)  # 첫 측정값 버리기
    last = psutil.net_io_counters()
    last_t = time.time()

    while True:
        time.sleep(INTERVAL)
        now = time.time()
        net = psutil.net_io_counters()
        elapsed = max(now - last_t, 0.001)
        traffic_in = round((net.bytes_recv - last.bytes_recv) * 8 / elapsed / 1_000_000, 3)
        last, last_t = net, now

        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        loss = measure_packet_loss()

        try:
            r = api("POST", "/api/agent/telemetry", json={
                "agent_id": agent_id, "cpu_usage": cpu, "ram_usage": ram,
                "traffic_in_mbps": traffic_in, "packet_loss": loss,
            })
            if r.status_code in (403, 404):
                print(f"[collector] 연결이 해제되었거나 미연결 상태입니다 ({r.status_code}). 다시 연결합니다.")
                wait_for_link(agent_id)
                continue
            r.raise_for_status()
            print(f"[collector] cpu={cpu}% ram={ram}% in={traffic_in}Mbps loss={loss}%")
        except requests.RequestException as e:
            print(f"[collector] 전송 실패, 다음 주기에 재시도: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[collector] 종료합니다.")
