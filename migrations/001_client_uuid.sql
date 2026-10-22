-- 001: 기기 식별을 IP 대신 브라우저 UUID(client_uuid)로 변경
-- 실행 전 반드시 백업: mysqldump -h <host> -P <port> -u <user> -p --single-transaction netmon > backup_before_001.sql
-- 실행 전 현재 인덱스 이름 확인: SHOW INDEX FROM devices;   (ux_devices_ip 가 있어야 함)

ALTER TABLE devices ADD COLUMN client_uuid VARCHAR(64) NULL AFTER ip;
ALTER TABLE devices DROP INDEX ux_devices_ip;
ALTER TABLE devices ADD INDEX idx_devices_ip (ip);
ALTER TABLE devices ADD UNIQUE KEY ux_devices_client_uuid (client_uuid);

-- 확인
SHOW INDEX FROM devices;
SELECT id, name, ip, client_uuid FROM devices;
