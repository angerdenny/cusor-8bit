SET NAMES utf8mb4;

DROP TABLE IF EXISTS endpoint_events;

CREATE TABLE endpoint_events (
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    action       VARCHAR(20)  NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    pid          INT          NULL,
    reason       VARCHAR(500) NOT NULL DEFAULT '',
    created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    KEY idx_endpoint_events_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO endpoint_events (action, process_name, pid, reason) VALUES
('block', 'unknown_tool.exe', 4321, '미인증 실행파일 감지'),
('allow', 'chrome.exe', 1024, '서명된 프로세스');