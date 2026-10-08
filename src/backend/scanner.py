"""LAN 스캐너: 같은 네트워크의 기기를 찾아 서버에 보고한다.
devices에 없는 IP면 대시보드에 등록 팝업이 뜬다. (에이전트가 필요 없다)"""
import ipaddress
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
if not AGENT_API_KEY:
    raise RuntimeError("AGENT_API_KEY가 .env에 없습니다.")
HEADERS = {"X-API-Key": AGENT_API_KEY}

SCAN_INTERVAL = 30  # 초
# 팝업에서 제외할 IP (공유기 등). 예: set IGNORE_IPS=192.168.35.1,192.168.35.2
IGNORE_IPS = {x.strip() for x in os.getenv("IGNORE_IPS", "").split(",") if x.strip()}
ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 실제로 패킷을 보내지는 않고 사용할 인터페이스만 정한다
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


MY_IP = local_ip()
# 대역을 직접 지정하려면: set SCAN_SUBNET=192.168.35.0/24
NET = ipaddress.ip_network(os.getenv("SCAN_SUBNET") or f"{MY_IP}/24", strict=False)


def ping(ip: str) -> None:
    subprocess.run(["ping", "-n", "1", "-w", "300", ip], capture_output=True)


def arp_hosts() -> dict[str, str]:
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="ignore").stdout
    found = {}
    for ip, mac in ARP_RE.findall(out):
        mac = mac.lower()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr not in NET or addr in (NET.network_address, NET.broadcast_address):
            continue
        if mac == "ff-ff-ff-ff-ff-ff" or mac.startswith("01-00-5e"):  # 브로드캐스트/멀티캐스트
            continue
        if ip == MY_IP or ip in IGNORE_IPS:
            continue
        found[ip] = mac
    return found


def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except Exception:
        return ""


def scan_once() -> dict[str, str]:
    hosts = [str(h) for h in NET.hosts()]
    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping, hosts))  # 핑 응답이 없어도 ARP 표에는 남는 경우가 많다
    return arp_hosts()


def main() -> None:
    print(f"[scanner] 시작: 서버={BACKEND}, 스캔 대역={NET}, 이 PC={MY_IP}")
    seen: set[str] = set()
    while True:
        try:
            found = scan_once()
            with ThreadPoolExecutor(max_workers=16) as ex:
                names = dict(zip(found, ex.map(hostname, found)))
            for ip, mac in found.items():
                name = names.get(ip) or f"새 기기-{ip.split('.')[-1]}"
                r = requests.post(f"{BACKEND}/api/agent/hello", headers=HEADERS, timeout=5,
                                  json={"ip": ip, "hostname": name})
                r.raise_for_status()
                if ip not in seen:
                    seen.add(ip)
                    state = "등록됨" if r.json().get("registered") else "미등록 → 대시보드에 팝업"
                    print(f"[scanner] 발견: {ip} ({name}, {mac}) {state}")
        except Exception as e:
            print(f"[scanner] 오류: {e}")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()