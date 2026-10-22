-- 002: 브라우저 연결 품질 측정용 ping_logs 테이블 보장 (이미 있으면 아무 일도 안 함)
CREATE TABLE IF NOT EXISTS ping_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  ok TINYINT(1) NOT NULL,
  rtt_ms DOUBLE NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_ping_dev (device_id, id)
);
