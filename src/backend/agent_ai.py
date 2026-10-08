"""AI 차단 명령 수신 에이전트: 서버의 승인 명령을 받아 프로세스를 종료한다.
기존 agent.py와 독립적으로 실행된다."""
import os
import socket
import subprocess
import time
from pathlib import Path

import psutil
import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
if not AGENT_API_KEY:
    raise RuntimeError("AGENT_API_KEY가 .env에 없습니다.")
HEADERS = {"X-API-Key": AGENT_API_KEY}
MY_IP = os.getenv("DEVICE_IP") or socket.gethostbyname(socket.gethostname())

# 절대 종료하면 안 되는 프로세스 (발표 전에 Chrome, IDE 등을 추가하세요)
PROTECTED = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
             "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", "dwm.exe", "mysqld.exe",
             "chrome.exe", "msedge.exe", "code.exe", "cursor.exe", "powershell.exe", "cmd.exe",
             "windowsterminal.exe", "conhost.exe"}
# 이 프로젝트 자신의 프로세스는 의심 후보에서 제외 (명령줄에 포함된 단어로 판별)
OWN_WORDS = ("uvicorn", "collector.py", "agent.py", "agent_ai.py", "init_db.py")


def safe_kill(pid: int, name: str, create_time: float | None) -> tuple[bool, str]:
    """PID 재사용, 시스템 프로세스 오종료를 막는 안전 검사 후 종료."""
    if pid in (0, 4, os.getpid(), os.getppid()):
        return False, "보호된 PID입니다"
    try:
        p = psutil.Process(pid)
        if p.name().lower() in PROTECTED:
            return False, "시스템 보호 프로세스입니다"
        if name and p.name().lower() != name.lower():
            return False, "프로세스 이름이 일치하지 않습니다 (PID 재사용 의심)"
        if create_time and abs(p.create_time() - create_time) > 1:
            return False, "프로세스 시작 시각이 다릅니다 (다른 프로세스)"
        p.kill()
        p.wait(timeout=3)
        return True, f"{name}({pid}) 종료됨"
    except psutil.NoSuchProcess:
        return True, "이미 종료된 프로세스입니다"
    except psutil.AccessDenied:
        return False, "권한 부족 (관리자 권한으로 실행 필요)"
    except Exception as e:
        return False, str(e)


def firewall_block(name: str, pid: int) -> tuple[bool, str]:
    """Windows 방화벽 아웃바운드 차단 (관리자 권한 필요)."""
    try:
        exe = psutil.Process(pid).exe()
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=NETMON_BLOCK_{name}", "dir=out", "action=block", f"program={exe}", "enable=yes"],
            capture_output=True, text=True)
        return r.returncode == 0, (r.stdout or r.stderr).strip()
    except Exception as e:
        return False, str(e)


def pick_suspect() -> dict | None:
    """CPU 사용률이 가장 높은 비보호 프로세스를 후보로 보고. (최종 판단은 관리자)"""
    best = None
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "create_time", "exe", "cmdline"]):
        i = p.info
        if not i["name"] or i["name"].lower() in PROTECTED or i["pid"] in (os.getpid(), os.getppid()):
            continue
        cmd = " ".join(i["cmdline"] or []).lower()
        if any(w in cmd for w in OWN_WORDS):
            continue
        if best is None or (i["cpu_percent"] or 0) > (best["cpu_percent"] or 0):
            best = i
    return best


def command_loop() -> None:
    device_id = None
    last_suspect = 0.0
    print(f"[agent_ai] 시작: 서버={BACKEND}, 이 기기 IP={MY_IP}")
    while True:
        try:
            if device_id is None:  # 미등록이면 hello를 계속 보내 대시보드에 등록 팝업이 뜨게 한다
                r = requests.post(f"{BACKEND}/api/agent/hello", headers=HEADERS, timeout=5,
                                  json={"ip": MY_IP, "hostname": socket.gethostname()})
                r.raise_for_status()
                r = r.json()
                if r.get("registered"):
                    device_id = r["device_id"]
                    print(f"[agent_ai] 등록된 기기입니다 (device_id={device_id})")
                else:
                    print("[agent_ai] 미등록 기기: 대시보드에서 등록을 기다리는 중...")
                    time.sleep(10)
                continue

            if time.time() - last_suspect > 5:
                s = pick_suspect()
                if s:
                    requests.post(f"{BACKEND}/api/agent/suspect", headers=HEADERS, timeout=5, json={
                        "device_id": device_id, "pid": s["pid"], "name": s["name"],
                        "create_time": s["create_time"], "exe": s["exe"] or ""})
                last_suspect = time.time()

            cmds = requests.get(f"{BACKEND}/api/agent/commands", headers=HEADERS, timeout=5,
                                params={"device_id": device_id}).json().get("commands", [])
            for c in cmds:
                if c["mode"] == "firewall":
                    ok, detail = firewall_block(c["name"], c["pid"])
                else:
                    ok, detail = safe_kill(c["pid"], c["name"], c.get("create_time"))
                print(f"[agent_ai] 차단 {'성공' if ok else '실패'}: {detail}")
                requests.post(f"{BACKEND}/api/agent/commands/{c['id']}/result", headers=HEADERS, timeout=5,
                              params={"incident_id": c["incident_id"]}, json={"ok": ok, "detail": detail})
        except Exception as e:
            print(f"[agent_ai] 오류: {e}")
        time.sleep(3)


if __name__ == "__main__":
    command_loop()