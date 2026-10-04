-- =====================================================================
--  8bit AI Pulse 통합 네트워크 관제 DB 스키마 (MySQL 8.0 기준)
-- =====================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------
-- 0. 기존 테이블/뷰 삭제
-- ---------------------------------------------------------------------
DROP VIEW  IF EXISTS v_latest_telemetry;
DROP TABLE IF EXISTS alert_devices;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS telemetry;
DROP TABLE IF EXISTS links;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS vlans;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- ---------------------------------------------------------------------
-- 1. users : 사용자 계정 및 권한 관리
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(50)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(10)  NOT NULL DEFAULT 'user',          -- 'admin' 또는 'user'
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY ux_users_username (username),
    CONSTRAINT ck_users_role CHECK (role IN ('admin', 'user'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 2. vlans : VLAN 구역
-- ---------------------------------------------------------------------
CREATE TABLE vlans (
    id          INT          NOT NULL AUTO_INCREMENT,
    code        VARCHAR(20)  NOT NULL,     
    name        VARCHAR(100) NOT NULL,
    cidr        VARCHAR(50)  NULL,
    color       CHAR(7)      NOT NULL DEFAULT '#a78bfa',
    created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY ux_vlans_code (code),  
    UNIQUE KEY ux_vlans_name (name),
    CONSTRAINT ck_vlans_color CHECK (LEFT(color, 1) = '#')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 3. devices : 관제 장비
-- ---------------------------------------------------------------------
CREATE TABLE devices (
    id          INT          NOT NULL AUTO_INCREMENT,
    name        VARCHAR(100) NOT NULL,
    ip          VARCHAR(45)  NOT NULL,
    type        VARCHAR(20)  NOT NULL DEFAULT 'server',
    owner_id    INT          NULL,                                -- users 테이블 참조
    x           DOUBLE       NULL,                                -- 맵 X 좌표(%)
    y           DOUBLE       NULL,                                -- 맵 Y 좌표(%)
    vlan_id     INT          NOT NULL,
    created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY ux_devices_ip (ip),
    KEY idx_devices_vlan (vlan_id),
    KEY idx_devices_owner (owner_id),

    CONSTRAINT fk_devices_vlan FOREIGN KEY (vlan_id) REFERENCES vlans (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_devices_owner FOREIGN KEY (owner_id) REFERENCES users (id)
        ON UPDATE CASCADE ON DELETE SET NULL,

    CONSTRAINT ck_devices_type CHECK (type IN ('router','switch','server','app','pc','mobile','firewall','printer','access-point'))
    CONSTRAINT ck_devices_x    CHECK (x IS NULL OR x BETWEEN -50 AND 150),
    CONSTRAINT ck_devices_y    CHECK (y IS NULL OR y BETWEEN -50 AND 150),
    CONSTRAINT ck_devices_xy   CHECK ((x IS NULL) = (y IS NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 4. links : 장비 연결 (토폴로지 선)
--    ※ MySQL은 외래키(CASCADE) 컬럼에 CHECK를 걸 수 없어서
--      "자기 자신과 연결 금지", "A-B / B-A 중복 금지"는 FastAPI에서 검사합니다.
-- ---------------------------------------------------------------------
CREATE TABLE links (
    source_id   INT         NOT NULL,
    target_id   INT         NOT NULL,
    created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (source_id, target_id),
    KEY idx_links_target (target_id),

    CONSTRAINT fk_links_source FOREIGN KEY (source_id) REFERENCES devices (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_links_target FOREIGN KEY (target_id) REFERENCES devices (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 5. telemetry : 실시간 텔레메트리/로그
-- ---------------------------------------------------------------------
CREATE TABLE telemetry (
    id               BIGINT      NOT NULL AUTO_INCREMENT,
    device_id        INT         NOT NULL,
    cpu_usage        DOUBLE      NOT NULL,
    ram_usage        DOUBLE      NOT NULL,
    traffic_in_mbps  DOUBLE      NOT NULL DEFAULT 0,
    packet_loss      DOUBLE      NOT NULL DEFAULT 0,
    `timestamp`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    KEY idx_telemetry_ts (`timestamp` DESC),
    KEY idx_telemetry_device_ts (device_id, `timestamp` DESC),

    CONSTRAINT fk_telemetry_device FOREIGN KEY (device_id) REFERENCES devices (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT ck_telemetry_cpu  CHECK (cpu_usage BETWEEN 0 AND 100),
    CONSTRAINT ck_telemetry_ram  CHECK (ram_usage BETWEEN 0 AND 100),
    CONSTRAINT ck_telemetry_in   CHECK (traffic_in_mbps >= 0),
    CONSTRAINT ck_telemetry_loss CHECK (packet_loss BETWEEN 0 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 6. alerts : 보안 및 AI 장애 로그
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
    id          INT          NOT NULL AUTO_INCREMENT,
    lv          VARCHAR(10)  NOT NULL DEFAULT 'info',
    title       VARCHAR(200) NOT NULL,
    msg         TEXT         NOT NULL,
    cause       VARCHAR(500) NOT NULL DEFAULT '',
    action      VARCHAR(500) NOT NULL DEFAULT '',
    `timestamp` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    KEY idx_alerts_ts (`timestamp` DESC),
    KEY idx_alerts_lv_ts (lv, `timestamp` DESC),

    CONSTRAINT ck_alerts_lv CHECK (lv IN ('ok', 'warn', 'crit', 'info'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE alert_devices (
    alert_id    INT NOT NULL,
    device_id   INT NOT NULL,

    PRIMARY KEY (alert_id, device_id),
    KEY idx_alert_devices_device (device_id),

    CONSTRAINT fk_alert_devices_alert  FOREIGN KEY (alert_id)  REFERENCES alerts  (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_alert_devices_device FOREIGN KEY (device_id) REFERENCES devices (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 7. 편의 뷰 : 장비별 최신 텔레메트리
-- ---------------------------------------------------------------------
CREATE VIEW v_latest_telemetry AS
SELECT t.device_id, t.cpu_usage, t.ram_usage, t.traffic_in_mbps, t.packet_loss, t.`timestamp`
FROM devices d
JOIN telemetry t
  ON t.id = (SELECT t2.id
               FROM telemetry t2
              WHERE t2.device_id = d.id
              ORDER BY t2.`timestamp` DESC, t2.id DESC
              LIMIT 1);

-- ---------------------------------------------------------------------
-- 8. 초기 기본 데이터 삽입
--    ※ password_hash는 임시로 평문입니다. 로그인 API 만들 때 해시로 교체합니다.
-- ---------------------------------------------------------------------
INSERT INTO users (username, password_hash, role) VALUES
('admin', '8bit', 'admin'),
('user1', '1234', 'user');

INSERT INTO vlans (id, code, name, cidr, color) VALUES
(1, 'Backbone (백본)', '192.168.1.0/24', '#22d3ee'),
(2, 'VLAN1 (Dev)', '10.0.0.0/24', '#a78bfa'),
(3, 'VLAN2 (Biz)', '192.168.1.0/25', '#fb923c');

INSERT INTO devices (id, name, ip, type, owner_id, x, y, vlan_id) VALUES
(1, 'Core Router 01', '192.168.1.1', 'router', 1, 50, 12, 1),
(2, 'Dist-SW-01', '192.168.1.10', 'switch', 1, 30, 44, 2),
(3, 'Dist-SW-02', '192.168.1.11', 'switch', 2, 70, 44, 3);

INSERT INTO links (source_id, target_id) VALUES
(1, 2),
(1, 3);

INSERT INTO telemetry (device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss) VALUES
(1, 45.2, 60.1, 120.5, 0.01),
(2, 82.0, 75.4, 450.0, 0.05),
(3, 22.1, 40.0, 15.2, 0.00);

INSERT INTO alerts (id, lv, title, msg, cause, action) VALUES
(1, 'crit', '[CRITICAL] 장애 위험 감지', 'Distribution SW 트래픽 급증 (AI 예측 확률 87.4%)', '분산 스위치 구간 트래픽 급증', '상위 링크 대역폭 점검');

INSERT INTO alert_devices (alert_id, device_id) VALUES (1, 2);
