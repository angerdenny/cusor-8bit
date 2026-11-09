"""가상 장비 생성 / 제거 (전시용)

각 계정에 가상 PC 1대씩을 만들고, 서버가 정상 범위의 CPU·메모리·트래픽을 계속 만들어 줘서
실제 환경 대시보드에서 계정별 장비가 움직이는 것처럼 보이게 한다.

사용법 (프로젝트 루트에서)
    python src/backend/seed_virtual_devices.py              # 만들기 (이미 있는 계정은 건너뜀)
    python src/backend/seed_virtual_devices.py --dry        # DB를 바꾸지 않고 무엇을 만들지만 보기
    python src/backend/seed_virtual_devices.py --no-links   # 장비 사이 연결선(별 모양)을 만들지 않음
    python src/backend/seed_virtual_devices.py --remove     # 가상 장비 모두 삭제 (전시 끝난 뒤)

위치: src/backend/seed_virtual_devices.py  (.env 의 DATABASE_URL 을 사용 — Render 와 같은 DB 여야 한다)
"""
import sys

from sqlalchemy import text

from database import engine

# 가상 장비를 만들 계정 (필요하면 여기를 수정)
USERNAMES = ["이지환", "김태현", "장우진", "양이수", "구본학", "박동연", "김민석", "최민규", "김범수"]
GRID_X = [22, 50, 78]
GRID_Y = [25, 50, 75]


def ensure_table(c):
    c.execute(text("CREATE TABLE IF NOT EXISTS virtual_devices (device_id INT PRIMARY KEY)"))


def remove(c):
    ids = [r[0] for r in c.execute(text("SELECT device_id FROM virtual_devices"))]
    for d in ids:
        c.execute(text("DELETE FROM devices WHERE id=:d"), {"d": d})   # 텔레메트리·연결선은 CASCADE 로 함께 삭제
    c.execute(text("DELETE FROM virtual_devices"))
    print(f"가상 장비 {len(ids)}대를 삭제했습니다.")


def main():
    dry = "--dry" in sys.argv
    with engine.begin() as c:
        if "--remove" in sys.argv:
            ensure_table(c)
            remove(c)
            return
        ensure_table(c)
        default_vlan = c.execute(text("SELECT id FROM vlans ORDER BY id LIMIT 1")).scalar()
        if default_vlan is None:
            sys.exit("vlans 테이블이 비어 있습니다. 구역(VLAN)이 먼저 있어야 합니다.")

        made, hub = [], None
        for i, name in enumerate(USERNAMES):
            u = c.execute(text("SELECT id, role FROM users WHERE username=:n"), {"n": name}).first()
            if not u:
                print(f"  - {name}: 계정을 찾지 못해 건너뜁니다")
                continue
            exist = c.execute(text("SELECT d.id FROM devices d JOIN virtual_devices v ON v.device_id=d.id "
                                   "WHERE d.owner_id=:u LIMIT 1"), {"u": u.id}).first()
            if exist:
                print(f"  = {name}: 이미 가상 장비가 있어 건너뜁니다 (장비 id {exist.id})")
                if u.role == "admin":
                    hub = exist.id
                continue
            vlan = c.execute(text("SELECT vlan_id FROM user_vlans WHERE user_id=:u ORDER BY vlan_id LIMIT 1"),
                             {"u": u.id}).scalar() or default_vlan
            dev_name = f"{name} PC (가상)"
            ip = f"10.88.0.{10 + i}"
            x, y = GRID_X[i % 3], GRID_Y[(i // 3) % 3]
            if dry:
                print(f"  + {name}: '{dev_name}' {ip} 구역 {vlan} 위치 ({x},{y})  [미리보기]")
                continue
            res = c.execute(text("INSERT INTO devices (name, ip, type, owner_id, x, y, client_uuid, vlan_id) "
                                 "VALUES (:n,:ip,'pc',:o,:x,:y,:cu,:v)"),
                            {"n": dev_name, "ip": ip, "o": u.id, "x": x, "y": y, "cu": f"virtual-{u.id}", "v": vlan})
            dev_id = res.lastrowid
            c.execute(text("INSERT INTO virtual_devices (device_id) VALUES (:d)"), {"d": dev_id})
            made.append(dev_id)
            if u.role == "admin" and hub is None:
                hub = dev_id
            print(f"  + {name}: '{dev_name}' 생성 (장비 id {dev_id}, 구역 {vlan})")

        if made and "--no-links" not in sys.argv and not dry:
            hub = hub or made[0]
            n_links = 0
            for d in made:
                if d != hub:
                    c.execute(text("INSERT IGNORE INTO links (source_id, target_id) VALUES (:a,:b)"), {"a": hub, "b": d})
                    n_links += 1
            print(f"  연결선 {n_links}개 생성 (중심 장비 id {hub})")
        print(f"\n완료: 새로 만든 가상 장비 {len(made)}대." if not dry else "\n미리보기 끝 (DB는 바뀌지 않았습니다).")


if __name__ == "__main__":
    main()
