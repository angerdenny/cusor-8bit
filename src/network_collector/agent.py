import os
import time
from dotenv import load_dotenv

import psutil
import requests
# .env 파일 로드
load_dotenv()
AGENT_API_KEY = "test_secret_key_12345"

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
SCAN_INTERVAL = 5  # 초

# 임시 폴더에서 실행되면서 이름이 여기에 있으면 종료(차단)합니다.
BLOCKLIST = {"test_tool.exe"}

WATCH_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.environ.get("TEMP", ""),
]
WATCH_DIRS = [os.path.normcase(d) for d in WATCH_DIRS if d]


def is_suspicious(exe_path):
    path = os.path.normcase(exe_path)
    result = any(path.startswith(d + os.sep) for d in WATCH_DIRS)
    # 디버그: 의심 프로세스 경로 확인
    if "test_tool" in exe_path.lower():
        print(f"[DEBUG] test_tool 감지: exe_path={exe_path}, WATCH_DIRS={WATCH_DIRS}, suspicious={result}")
    return result


def send_event(action, name, pid, reason):
    try:
        res = requests.post(
            f"{API_URL}/api/endpoint-security/events",
            json={
                "action": action,
                "process_name": name,
                "pid": pid,
                "reason": reason,
            },
            timeout=5,
        )
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"서버 전송 실패: {e}")


def block(proc, name, pid):
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except psutil.NoSuchProcess:
        pass
    except (psutil.AccessDenied, psutil.TimeoutExpired) as e:
        print(f"차단 실패: {name} (pid={pid}) {e}")
        return False
    return True


def scan(reported):
    found = 0
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        info = proc.info
        exe = info.get("exe")
        name = info.get("name") or ""
        if not exe or not is_suspicious(exe):
            continue
        found += 1
        key = (info["pid"], exe)
        if key in reported:
            continue
        reported.add(key)
        if name.lower() in BLOCKLIST:
            if block(proc, name, info["pid"]):
                print(f"[차단] pid={info['pid']} name={name} path={exe}")
                send_event(
                    "block", name, info["pid"], "임시 폴더에서 실행된 차단 목록 프로세스"
                )
        else:
            print(f"[의심] pid={info['pid']} name={name} path={exe}")
    return found


if __name__ == "__main__":
    print("감시를 시작합니다. 중지하려면 Ctrl+C")
    reported = set()
    try:
        while True:
            count = scan(reported)
            print(f"스캔 완료: 의심 프로세스 {count}개")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("감시를 종료합니다.")