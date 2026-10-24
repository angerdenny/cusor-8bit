# -*- coding: utf-8 -*-
"""엔드포인트 보안 감시 에이전트 (노트북에서 실행, 관리자 PowerShell 권장)

흐름
1. 감시 목록과 정확히 같은 이름의 프로세스를 찾는다.
2. 탐지 사실을 /api/endpoint-security/events 에 action="detected" 로 보고한다.
3. 같은 프로세스를 /api/agent/suspect 에 보고한다 (AI 경보와 연결됨).
4. 관리자가 대시보드에서 승인하면 /api/agent/commands 로 명령을 받아
   PID + 이름 + 생성 시각이 모두 일치할 때만 종료하고 결과를 보고한다.
"""
import os
import socket
import sys
import time
from pathlib import Path

import psutil
import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BACKEND = os.getenv("BACKEND_URL", "https://cusor-8bit.onrender.com").rstrip("/")
AGENT_KEY = os.getenv("AGENT_API_KEY")
if not AGENT_KEY:
    sys.exit("AGENT_API_KEY가 .env에 없습니다.")
HEADERS = {"X-API-Key": AGENT_KEY}

INTERVAL = 5  # 초

# 감시 목록: 이름이 정확히 같을 때만 탐지 (부분 문자열 매칭 금지)
SUSPICIOUS_NAMES = {"nc.exe", "psexec.exe", "mimikatz.exe", "backdoor.exe", "ransomware.exe"}

# 종료하면 안 되는 시스템 프로세스 (이름 기준, 소문자)
PROTECTED_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe",
}

device_id = None   # 서버에서 받은 이 PC의 장비 id
reported_pids = set()


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 패킷은 보내지 않고 인터페이스만 고른다
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def api(method: str, path: str, **kwargs):
    r = requests.request(method, BACKEND + path, headers=HEADERS, timeout=8, **kwargs)
    r.raise_for_status()
    return r.json()


def ensure_device_id() -> None:
    """hello 호출로 이 PC의 device_id를 얻는다. 미등록이면 None 유지."""
    global device_id
    if device_id is not None:
        return
    r = api("POST", "/api/agent/hello", json={"ip": local_ip(), "hostname": socket.gethostname()})
    if r.get("registered"):
        device_id = r["device_id"]
        print(f"[agent] 장비 확인: device_id={device_id}")
    else:
        print("[agent] 아직 미등록 장비입니다. 대시보드에서 등록 승인 후 다시 시도합니다.")


def is_protected(pid: int, name_lower: str) -> bool:
    return pid is None or pid <= 4 or pid == os.getpid() or name_lower in PROTECTED_NAMES


def send_event(action: str, name: str, pid: int, reason: str) -> None:
    try:
        api("POST", "/api/endpoint-security/events",
            json={"action": action, "process_name": name, "pid": pid, "reason": reason})
        print(f"[agent] 이벤트 전송 | {action} | {name} | PID {pid}")
    except Exception as e:
        print(f"[agent] 이벤트 전송 실패: {e}")


def scan_suspicious() -> list[dict]:
    found = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            info = p.info
            name = info["name"] or ""
            if is_protected(info["pid"], name.lower()):
                continue
            if name.lower() in SUSPICIOUS_NAMES:
                found.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return found


def report_suspicious(found: list[dict]) -> None:
    current = {f["pid"] for f in found}
    reported_pids.intersection_update(current)  # 끝난 프로세스는 기록에서 제거

    for info in found:
        pid, name = info["pid"], info["name"]

        # 1) 이벤트 로그 (처음 발견했을 때 한 번만)
        if pid not in reported_pids:
            reported_pids.add(pid)
            send_event("detected", name, pid, f"Suspicious process detected: {name}")

        # 2) 의심 프로세스 정보 (AI 경보와 연결되도록 주기적으로 갱신)
        if device_id is not None:
            try:
                api("POST", "/api/agent/suspect", json={
                    "device_id": device_id, "pid": pid, "name": name,
                    "create_time": info["create_time"], "exe": "",
                })
            except Exception as e:
                print(f"[agent] 의심 프로세스 보고 실패: {e}")


def try_kill(cmd: dict) -> tuple[bool, str]:
    """승인된 명령 실행. PID, 이름, 생성 시각이 모두 맞을 때만 종료한다."""
    if cmd.get("mode") != "kill":
        return False, f"지원하지 않는 모드: {cmd.get('mode')}"

    pid = cmd.get("pid")
    name = (cmd.get("name") or "")
    name_lower = name.lower()
    if is_protected(pid, name_lower):
        return False, "보호된 시스템 프로세스라 종료하지 않음"

    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False, "프로세스가 이미 종료되어 있음"
    except psutil.AccessDenied:
        return False, "권한 부족 (관리자 PowerShell로 실행해야 함)"

    try:
        if p.name().lower() != name_lower:
            return False, "PID의 프로세스 이름이 달라 종료하지 않음"
        ct = cmd.get("create_time")
        if ct and abs(p.create_time() - ct) > 1:
            return False, "PID가 재사용되어 종료하지 않음"

        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
        return True, f"{name}(PID {pid}) 종료 완료"
    except psutil.AccessDenied:
        return False, "권한 부족으로 종료 실패"
    except psutil.NoSuchProcess:
        return True, f"{name}(PID {pid}) 종료 완료"


def poll_commands() -> None:
    if device_id is None:
        return
    data = api("GET", "/api/agent/commands", params={"device_id": device_id})
    for cmd in data.get("commands", []):
        ok, detail = try_kill(cmd)
        print(f"[agent] 차단 명령 {cmd.get('id', '')[:8]} | {'성공' if ok else '실패'} | {detail}")
        api("POST", f"/api/agent/commands/{cmd['id']}/result",
            params={"incident_id": cmd["incident_id"]},
            json={"ok": ok, "detail": detail})


def check_backend() -> None:
    try:
        r = requests.get(BACKEND + "/api/health", timeout=10)
        status = r.json().get("status", "?")
        print(f"[✓] 백엔드 상태: {status}")
    except Exception as e:
        print(f"[!] 백엔드 확인 실패: {e}")


def main() -> None:
    print("=" * 60)
    print("엔드포인트 보안 감시 에이전트 시작")
    print("=" * 60)
    print(f"백엔드 URL: {BACKEND}")
    print(f"감시 프로세스: {', '.join(sorted(SUSPICIOUS_NAMES))}")
    print("=" * 60)
    check_backend()

    while True:
        try:
            ensure_device_id()
            report_suspicious(scan_suspicious())
            poll_commands()
        except Exception as e:
            print(f"[agent] 오류: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agent] 종료합니다.")
