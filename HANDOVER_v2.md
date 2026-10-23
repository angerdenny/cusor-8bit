# 8bit AI Pulse 인수인계 v2 (최종)

> 이 문서는 새 채팅에서 첫 메시지로 함께 올려 주세요. 비밀 값(DB 비밀번호, JWT_SECRET, AGENT_API_KEY, 계정 비밀번호)은 적지 않습니다. 필요하면 직접 확인해서 알려 주세요.

## 1. 기본 정보
- 사용자: 지현(jihya), Windows 11, PowerShell
- 저장소: https://github.com/angerdenny/cusor-8bit.git (브랜치 main)
- 발표: **2026-10-27** (학교 프로젝트). 구조 변경보다 발표에서 확실히 동작하는 것이 우선.
- 작업 방식: 명령은 한 번에 하나씩, 결과를 보고 다음 단계로.

## 2. 시스템 구성
| 구성 | 역할 |
|---|---|
| Render (무료) | 백엔드 + 대시보드. 헬스체크 `/api/health` |
| Aiven MySQL 8.0 | 운영 DB. DB 이름 **`defaultdb`** |
| 노트북 (Windows) | `collector.py`(PC 측정), `agent.py`(프로세스 감시), `scanner.py`(LAN 탐색), `pinger.py`(등록 기기 핑) |
| 스마트폰/아이패드 | 브라우저 접속. 응답 시간(ms)과 실패 여부만 5초마다 보고. CPU/메모리는 측정 불가 |

로컬 테스트: `uvicorn main:app --host 127.0.0.1 --port 8000` (**워커 1개**), 주소 `http://127.0.0.1:8000/?env=real`
(`?env=real`이 없으면 더미 시뮬레이션 화면)

## 3. 파일 위치 (저장소 기준)
| 파일 | 위치 |
|---|---|
| `main.py`, `ai_routes.py`, `models.py`, `database.py`, `pinger.py` | `src/backend/` |
| `detector.py` (Isolation Forest) | `src/ai/` (모델 파일은 `src/ai/models/`, Git 제외) |
| `index.html` | `public/` |
| `requirements.txt`, `.env.example`, `.gitignore` | 저장소 루트 |
| `migrations/001_client_uuid.sql`, `002_ping_logs.sql` | `migrations/` |
| `schema.sql` | 기존 위치 유지 (경고문 포함) |
| `collector.py`, `scanner.py`, `agent.py` | 노트북 실행 폴더 (위치 확인 후 기록) |

## 4. 운영 DB 주의 (가장 중요)
- **`schema.sql`은 운영 DB에 재실행 금지.** 맨 위 `DROP TABLE`이 기기, 계정, 로그를 모두 지웁니다.
- DB 변경은 `migrations/`의 번호 붙은 SQL로만 합니다. 실행 전 백업:
  `mysqldump -h <host> -P <port> -u <user> -p --single-transaction defaultdb > backup_before_XXX.sql`
  실행은 PowerShell에서 `Get-Content 파일.sql | mysql ...` (`<` 리다이렉션은 안 됨).
- 실행 완료: `001_client_uuid.sql` (**재실행 금지**, ADD COLUMN 중복으로 실패함), `002_ping_logs.sql` (IF NOT EXISTS, 재실행 안전).

## 5. 테이블 (11개 + 뷰 1개)
`users`, `vlans`, `devices`, `links`, `telemetry`, `alerts`, `alert_devices`, `user_vlans`, `endpoint_events`, `ai_incidents`, `ping_logs` + 뷰 `v_latest_telemetry`

- `vlans.code` 값은 프론트 `vlan_code`와 같아야 합니다: `100`, `101`, `102`.
- 원래 스펙의 `network_logs`, `ai_alerts`는 실제로 `telemetry`, `ai_incidents` + `alerts`로 구현됨. 발표 자료도 이 이름으로 통일.
- ORM(`models.py`)은 `users`, `vlans`, `devices`, `links`, `telemetry`, `alerts`, `alert_devices`만 다룸. 나머지는 raw SQL.

## 6. 환경변수 (`.env.example` 참고, 값은 채팅에 쓰지 않음)
- 필수 (코드에서 없으면 시작 실패): `DATABASE_URL`, `JWT_SECRET`, `AGENT_API_KEY`
- 토큰: `JWT_ALGORITHM`(HS256), `JWT_EXPIRE_MINUTES`(기본 30)
- `AUTO_ENROLL_VLAN`: 설정하면 등록 요청이 **승인 없이 바로 등록**됨. 발표 승인 장면에서는 **비워 둘 것**. 발표 전날 Render에서 비었는지 확인.
- `AI_TRAIN_DEVICE_ID`: AI 학습 장비. 비우면 전체 텔레메트리로 학습.
- 노트북용: `BACKEND_URL`, `COLLECT_DEVICE_NAME`(고유하게), `COLLECT_VLAN_ID`, `COLLECT_INTERVAL_SEC`, `PING_TARGET`, `SCAN_SUBNET`, `IGNORE_IPS`
- 사용하지 않는 키는 제거됨 (`SECRET_KEY`, `FAILED_LOGIN_ATTEMPTS` 등). 로그인 제한은 코드 고정값(10회, 1시간).

## 7. 기능 상태
| 기능 | 상태 |
|---|---|
| 로그인 (admin 계정 존재) | 정상 |
| 기기 등록: 브라우저 UUID(`X-Device-Id`)로 구분 | 정상 (테스트 완료) |
| 등록 요청 → 관리자 승인 → 토폴로지 추가 | 정상 (테스트 완료) |
| 기기 간 연결 요청 → 모바일 승인 → 연결선 | 정상 |
| 스마트폰 응답 시간 측정 (`/api/ai/heartbeat`) | 정상 |
| 보고 끊김 약 20초 후 offline 판정 | 코드 반영, 실제 와이파이 끊김 테스트 **미완** |
| 백업 저장(JSON) / 복구(`RESTORE` 입력) | 정상 확인 |
| 엔드포인트 감시 이벤트 (`/api/endpoint-security/events`) | GET/POST 구현됨, `agent.py`로 실제 전송 **검증 필요** |
| 재학습(오탐 피드백) 버튼 | 상태 코드(200/400/403) **미확인** |
| 시나리오 5 (차단 승인 → agent가 프로세스 종료) | **미검증** (노트북 agent.py 실행 필요) |

## 8. 설계 핵심
- **기기 식별**: 브라우저가 만든 UUID를 `X-Device-Id`로 보냄. `devices.client_uuid`(UNIQUE). `devices.ip`는 UNIQUE가 아님.
- **측정 구분**: PC는 `collector.py`가 psutil로 실제 값 저장. 스마트폰은 `ping_logs`에 응답 시간만 저장. `pinger.py`는 `client_uuid IS NULL`인 기기만 핑.
- **승인 흐름**: 등록 요청은 `_pending`에 저장되고 `requested=True`인 것만 관리자 팝업. 연결 요청은 모바일 기기가 승인.
- **AI 위험 스코어**: Isolation Forest. 특성은 CPU, 메모리, 트래픽, 지연, 손실. 단, `ping` 특성은 텔레메트리에 없어 항상 0이고 `loss`도 대부분 0. **실제 판단은 CPU, 메모리, 트래픽 중심**이라고 설명할 것.
- **백업/복구**: 백업은 users(해시 포함), vlans, devices, links, user_vlans. 측정 기록은 제외. 복구는 트랜잭션이며 실패 시 롤백.

## 9. 알려진 한계 (발표 설명 또는 문서에 명시)
1. **인메모리 상태**: `_pending`, `_commands`, `_conn_reqs`, 로그인 실패 기록은 프로세스 메모리에만 있음. 서버 재시작 시 사라짐. 워커는 1개로 고정.
2. **로그인 실패 제한은 계정명 기준** (수정 반영). IP 기준이었을 때는 Render 프록시 IP가 전부 같아서 한 사람의 실패가 모든 사용자를 막았음. 대신 같은 계정에 대한 잠금은 여러 사람이 악용할 수 있음 (시연 범위에서는 허용).
3. **같은 IP 조회**: `/api/agent/hello`는 `WHERE ip=:ip`로 찾음. 같은 IP 기기가 여럿이면 잘못 선택될 수 있음.
4. **백업 복구 = 측정 이력 삭제**: 복구 시 `devices` 삭제가 `telemetry`를 CASCADE로 지움.
5. **Windows 전용**: `pinger.py`, `scanner.py`, `collector.py`의 ping/arp 옵션은 Windows 기준. Render에서 실행하지 않음.
6. **모델 파일은 Git 제외**: Render 재배포 시 모델이 사라지고 텔레메트리 50건 이상 쌓이면 다시 학습.
7. **레거시 API**: `/api/devices/pending`, `/api/devices/enroll`, `/api/dashboard/overview`는 `devices.status` 컬럼을 쓰지만 현재 스키마에 없음. 프론트에서 호출하지 않음. 호출하면 500. 운영 DB에 `status` 컬럼이 있는지 확인 전까지는 사용 금지.
8. **`/api/endpoint-security/events` GET**: 로그인한 모든 사용자가 구역 구분 없이 조회 가능. 발표 후 관리자 전용으로 변경 권장.
9. **`X-Forwarded-For`**: 기기 IP 표시용으로만 씀. 식별이나 차단 판단에 쓰지 않음.

## 10. 발표 전 체크리스트
- [ ] Render 환경변수: `AUTO_ENROLL_VLAN` 비어 있음, 불필요 키 제거
- [ ] 노트북 `AGENT_API_KEY`와 Render 값 일치
- [ ] 등록 요청 1회 테스트: 승인 팝업이 뜨는지
- [ ] 로그인 실패 제한: 한 계정에서 틀려도 다른 계정이 잠기지 않는지
- [ ] 아이패드 Wi-Fi 끊기 → 약 20초 뒤 offline 표시
- [ ] 시나리오 5 리허설: agent.py 실행 → 차단 승인 → 프로세스 종료
- [ ] 재학습 버튼: Network 탭에서 상태 코드 확인
- [ ] 백업 파일은 USB 등 개인 매체에만 보관, `backup/` 커밋 금지 (`git ls-files backup/` 결과 비어 있어야 함)
- [ ] 발표 당일: 서버 깨우기(대시보드 열기), scanner.py 끄기, 아이패드 Ctrl+F5, 노트북 agent.py 실행

## 11. 커밋 규칙
`feat:`, `fix:`, `docs:`, `style:` (선택: `refactor:`). 예:
- `fix: 로그인 실패 제한을 계정명 기준으로 변경`
- `fix: TRAIN_SQL 장비 ID 하드코딩 제거`
- `fix: vlans 시드 컬럼 수 불일치 수정`
- `fix: database.py .env 경로를 파일 기준으로 고정`
- `docs: 인수인계 v2, 환경변수 예시 정리`
- `docs: schema.sql 운영 DB 재실행 금지 경고 추가`
- `style: .gitignore 보강, requirements에서 미사용 패키지 제거`

## 12. 남은 작업 (우선순위)
1. 운영 DB의 `devices.status` 컬럼 존재 여부 확인 (`SHOW COLUMNS FROM devices;`)
2. `agent.py` 점검: `AGENT_API_KEY` 사용, 차단 실행, 엔드포인트 이벤트 전송
3. 운영 DB의 `vlans.code`가 `100/101/102`인지 확인 (`SELECT id, code, name FROM vlans;`)
4. 발표용 기기 등록 (노트북 `pc`, 모바일 1~2대 `mobile`)
5. 발표 시연 순서 리허설
