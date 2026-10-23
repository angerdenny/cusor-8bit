-- 001: 기기 식별을 IP 대신 브라우저 UUID(client_uuid)로 변경
-- 상태: 운영 DB(defaultdb)에 실행 완료. 재실행 금지 (ADD COLUMN 중복으로 실패함)
-- 기록용으로 보관. 새 DB를 만들 때는 schema.sql 을 사용.
--
-- 백업 명령 (이 프로젝트의 DB 이름은 defaultdb):
--   mysqldump -h <host> -P <port> -u <user> -p --single-transaction defaultdb > backup_before_XXX.sql

ALTER TABLE devices ADD COLUMN client_uuid VARCHAR(64) NULL AFTER ip;
ALTER TABLE devices DROP INDEX ux_devices_ip;
ALTER TABLE devices ADD INDEX idx_devices_ip (ip);
ALTER TABLE devices ADD UNIQUE KEY ux_devices_client_uuid (client_uuid);

-- 확인
SHOW INDEX FROM devices;
SELECT id, name, ip, client_uuid FROM devices;
