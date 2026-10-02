"""
엔드포인트 보안 감시 에이전트
- psutil을 사용한 의심 프로세스 감시
- FastAPI 백엔드로 이벤트 전송 (X-API-Key 검증)
- 5초 간격 폴링
"""

import os
import time
import requests
import psutil
from datetime import datetime
from dotenv import load_dotenv

# ========================
# 환경 변수 로드
# ========================
load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "your_secure_agent_api_key_change_this")

# 의심 프로세스 목록 (예시)
SUSPICIOUS_PROCESSES = [
    "cmd.exe",           # 명령 프롬프트
    "powershell.exe",    # PowerShell (의심 실행일 경우)
    "wscript.exe",       # VBScript
    "cscript.exe",       # JavaScript
    "python.exe",        # Python (테스트용, 실제론 제거)
    "nc.exe",            # netcat
    "psexec.exe",        # PsExec
    "mimikatz.exe",      # 크리덴셜 탈취
]

# 이미 보고된 프로세스 추적
reported_pids = set()

# ========================
# 함수: 의심 프로세스 감시
# ========================
def check_suspicious_processes():
    """
    현재 실행 중인 프로세스를 감시하고
    의심 프로세스 발견 시 백엔드로 이벤트 전송
    """
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            process_name = proc.info['name'].lower()
            
            # 의심 프로세스 확인
            if any(suspicious in process_name for suspicious in SUSPICIOUS_PROCESSES):
                # 이미 보고했으면 스킵
                if pid in reported_pids:
                    continue
                
                # 백엔드로 이벤트 전송
                send_event_to_backend(
                    action="blocked",
                    process_name=proc.info['name'],
                    pid=pid,
                    reason=f"Suspicious process detected: {process_name}"
                )
                
                # 보고됨 표시
                reported_pids.add(pid)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # 프로세스가 종료됐거나 접근 불가
            pass

# ========================
# 함수: 백엔드에 이벤트 전송
# ========================
def send_event_to_backend(action, process_name, pid, reason):
    """
    FastAPI 백엔드로 엔드포인트 이벤트 전송
    
    POST /api/endpoint-security/events
    헤더: X-API-Key: <AGENT_API_KEY>
    """
    url = f"{BACKEND_URL}/api/endpoint-security/events"
    
    headers = {
        "X-API-Key": AGENT_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "action": action,
        "process_name": process_name,
        "pid": pid,
        "reason": reason
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print(f"[✓] 이벤트 전송 성공 | PID: {pid} | 프로세스: {process_name} | 이벤트ID: {data.get('id')}")
        elif response.status_code == 401:
            print(f"[✗] API 키 검증 실패 | 응답: {response.json()}")
        else:
            print(f"[✗] 전송 실패 | 상태 코드: {response.status_code} | {response.text}")
    
    except requests.exceptions.ConnectionError:
        print(f"[✗] 백엔드 연결 실패 | URL: {url}")
    except Exception as e:
        print(f"[✗] 오류 발생: {str(e)}")

# ========================
# 함수: 백엔드 헬스 체크
# ========================
def check_backend_health():
    """백엔드 서버 상태 확인"""
    url = f"{BACKEND_URL}/api/health"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[✓] 백엔드 상태: {data['status']}")
            return True
    except Exception as e:
        print(f"[✗] 백엔드 연결 실패: {str(e)}")
        return False

# ========================
# 메인 루프
# ========================
def main():
    """에이전트 메인 루프"""
    print("=" * 60)
    print("엔드포인트 보안 감시 에이전트 시작")
    print("=" * 60)
    print(f"백엔드 URL: {BACKEND_URL}")
    print(f"감시 프로세스: {', '.join(SUSPICIOUS_PROCESSES)}")
    print("=" * 60)
    
    # 초기 헬스 체크
    if not check_backend_health():
        print("[!] 경고: 백엔드 서버에 연결할 수 없습니다.")
        print("[!] 서버를 시작해주세요: uvicorn main:app --reload")
        return
    
    print("[✓] 감시 시작 (5초 간격)\n")
    
    try:
        while True:
            check_suspicious_processes()
            time.sleep(5)
    
    except KeyboardInterrupt:
        print("\n[✓] 에이전트 종료됨")
    
    except Exception as e:
        print(f"\n[✗] 예상치 못한 오류: {str(e)}")

# ========================
# 실행
# ========================
if __name__ == "__main__":
    main()
