# -*- coding: utf-8 -*-
"""Telemetry collector: measures this PC and inserts a row into telemetry every N seconds."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import psutil
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv(Path(__file__).resolve().parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    sys.exit("Missing DATABASE_URL in .env")

INTERVAL = int(os.getenv("COLLECT_INTERVAL_SEC", "5"))
DEVICE_NAME = os.getenv("COLLECT_DEVICE_NAME", socket.gethostname())

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def get_local_ip() -> str:
    """Best-effort local IP (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def get_or_create_device() -> int:
    """Find this PC in devices by name, or register it. Returns device id."""
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id FROM devices WHERE name = :n"), {"n": DEVICE_NAME}
        ).fetchone()
        if row:
            return row[0]
        result = conn.execute(
            text("INSERT INTO devices (name, ip, type, vlan_id) VALUES (:n, :ip, :t, :v)"),
            {
                "n": DEVICE_NAME,
                "ip": get_local_ip(),
                "t": "pc",
                "v": int(os.getenv("COLLECT_VLAN_ID", "1")),
            },
        )
        return result.lastrowid


def measure_packet_loss() -> float:
    """Ping the gateway-ish target once; returns 0.0 (ok) or 100.0 (lost)."""
    target = os.getenv("PING_TARGET", "8.8.8.8")
    flag = "-n" if os.name == "nt" else "-c"
    try:
        r = subprocess.run(
            ["ping", flag, "1", target],
            capture_output=True,
            timeout=3,
        )
        return 0.0 if r.returncode == 0 else 100.0
    except (subprocess.TimeoutExpired, OSError):
        return 100.0


def main():
    device_id = get_or_create_device()
    print(f"[collector] device '{DEVICE_NAME}' id={device_id}, interval={INTERVAL}s (Ctrl+C to stop)")

    psutil.cpu_percent(interval=None)  # prime the counter
    last = psutil.net_io_counters()
    last_t = time.time()

    while True:
        time.sleep(INTERVAL)

        now = time.time()
        net = psutil.net_io_counters()
        elapsed = max(now - last_t, 0.001)
        # received bytes/sec -> Mbps
        traffic_in_mbps = round((net.bytes_recv - last.bytes_recv) * 8 / elapsed / 1_000_000, 3)
        last, last_t = net, now

        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        loss = measure_packet_loss()

        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO telemetry (device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss)
                        VALUES (:d, :c, :r, :t, :p)
                    """),
                    {"d": device_id, "c": cpu, "r": ram, "t": traffic_in_mbps, "p": loss},
                )
            print(f"[collector] cpu={cpu}% ram={ram}% in={traffic_in_mbps}Mbps loss={loss}%")
        except Exception as e:
            print(f"[collector] DB insert failed: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[collector] stopped")