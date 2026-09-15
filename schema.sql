-- DB 생성 및 선택 (필요 시 주석 해제하여 사용)
-- CREATE DATABASE IF NOT EXISTS network_monitoring;
-- USE network_monitoring;

-- 1. 기존 테이블이 존재할 경우 삭제 (순서 주의: 외래키 참조 역순)
DROP TABLE IF EXISTS ai_alerts;
DROP TABLE IF EXISTS network_logs;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;

-- =========================================================
-- 2. 사용자 테이블 (users)
-- 계정 정보 및 권한(관리자/일반 사용자) 구분
-- =========================================================
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- 3. 장비/기기 등록 테이블 (devices)
-- 수집 대상 장비 및 접속 기기 자동 등록 정보 저장
-- =========================================================
CREATE TABLE devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    device_type ENUM('router', 'switch', 'server', 'pc', 'mobile') NOT NULL DEFAULT 'pc',
    status ENUM('online', 'warning', 'offline') NOT NULL DEFAULT 'online',
    owner_id INT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =========================================================
-- 4. 실시간 네트워크 트래픽 로그 테이블 (network_logs)
-- 파이썬 수집 모듈이 periodic하게 데이터를 삽입하는 공간
-- =========================================================
CREATE TABLE network_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    cpu_usage FLOAT NOT NULL DEFAULT 0.0,
    memory_usage FLOAT NOT NULL DEFAULT 0.0,
    traffic_in_mbps FLOAT NOT NULL DEFAULT 0.0,
    traffic_out_mbps FLOAT NOT NULL DEFAULT 0.0,
    packet_loss_rate FLOAT NOT NULL DEFAULT 0.0,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- =========================================================
-- 5. AI 장애 예측 알림 테이블 (ai_alerts)
-- AI 모델이 이상 징후 감지 시 알림 내역을 저장하는 공간
-- =========================================================
CREATE TABLE ai_alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    alert_level ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'warning',
    failure_probability FLOAT NOT NULL, -- AI가 계산한 장애 발생 확률 (%)
    message VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- =========================================================
-- 6. 초기 테스트 데이터 (기초 데이터 삽입)
-- =========================================================

-- 초기 계정 추가 (비밀번호는 추후 해시화 처리 예정)
INSERT INTO users (username, password_hash, role) VALUES 
('admin', '8bit', 'admin'),
('user1', '1234', 'user');

-- 초기 관제 대상 핵심 네트워크 장비 추가
INSERT INTO devices (device_name, ip_address, device_type, status, owner_id) VALUES 
('Core Router', '192.168.1.1', 'router', 'online', 1),
('Distribution SW', '192.168.1.2', 'switch', 'warning', 1),
('Access SW', '192.168.1.10', 'switch', 'online', 1);

-- 테스트용 초기 네트워크 수집 로그 데이터
INSERT INTO network_logs (device_id, cpu_usage, memory_usage, traffic_in_mbps, traffic_out_mbps) VALUES 
(1, 45.2, 60.1, 120.5, 95.2),
(2, 82.0, 75.4, 450.0, 380.1),
(3, 22.1, 40.0, 15.2, 10.1);

-- 테스트용 AI 장애 경고 데이터
INSERT INTO ai_alerts (device_id, alert_level, failure_probability, message) VALUES 
(2, 'critical', 87.0, 'Distribution SW 인터페이스 트래픽 급증 (AI 예측 장애 확률 87%)'),
(1, 'warning', 65.0, 'Core Router CPU 사용량 80% 달성');