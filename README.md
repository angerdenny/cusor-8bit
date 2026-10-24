# 8bit AI Pulse · AI 기반 네트워크 관제 시스템

네트워크 장비와 PC의 상태(CPU, 메모리, 트래픽, 응답 시간)를 한 화면에서 보고, AI로 장애 위험을 예측하며, 관리자가 승인한 보안 차단을 실행하는 관제 시스템입니다.

- 서버와 대시보드: Render (https://cusor-8bit.onrender.com)
- 데이터베이스: Aiven MySQL 8.0
- 발표: 2026-10-27 (학교 프로젝트)

---

## 1. 팀 역할

화면의 "팀원 담당 역할" 카드 기준입니다.

| 역할 | 담당자 | 주요 관련 파일 |
|---|---|---|
| 총괄 · 권한 관리 | 이지환 | `src/backend/main.py` (로그인, 권한), `src/backend/agent_link.py` (회원가입, PC 연결, 탈퇴) |
| UI · 대시보드 | 장우진 | `public/index.html` (대시보드 화면) |
| 네트워크 토폴로지 | 양이수 | `public/index.html` (토폴로지 화면, 장비 좌표) |
| 로그 수집 | 김범수 | `src/backend/collector.py`, `agent.py`, `scanner.py`, `pinger.py` |
| 백엔드 · 경보 | 구본학 | `src/backend/ai_routes.py` (경보, 차단 명령, 에이전트 API), `main.py` (알림, 엔드포인트 이벤트) |
| 관제 DB · ETL | 김민석 | `schema.sql`, `migrations/`, `src/backend/models.py`, `database.py`, 백업·복구 API |
| AI 예측 · 분석 | 최민규, 김태현 | `src/ai/detector.py` (Isolation Forest), `ai_routes.py` (학습, 위험 점수) |
| 트래픽 최적화 | 박동연 | 트래픽 · AI 분석 화면 (`public/index.html`), 트래픽 관련 처리 (담당 파일은 본인 확인 필요) |

> 위 "관련 파일"은 역할 기준의 대략적인 영역입니다. 실제로 누가 어떤 코드를 썼는지는 아래 명령으로 확인할 수 있습니다.
>
> ```
> git shortlog -sn
> git log --format="%an | %s" -- src/backend/ai_routes.py
> ```

---

## 2. 전체 구성

```
[다른 PC]  collector.py ──(API, AGENT_API_KEY)──┐
[노트북]   collector.py / agent.py / scanner.py ─┤
[브라우저] 대시보드 (로그인 사용자) ─────────────┼──> [Render: FastAPI 서버] ──> [Aiven MySQL]
[아이패드] 브라우저 (응답 시간 보고) ────────────┘
```

- 서버는 DB 비밀번호를 가지고 있고, 다른 PC는 DB에 직접 접속하지 않습니다. 모든 보고는 서버 API로만 합니다.
- 측정 방식은 기기 종류마다 다릅니다.
  - PC: `collector.py`가 CPU, 메모리, 수신 트래픽, 패킷 손실을 측정해서 보냅니다.
  - 스마트폰/아이패드: 브라우저가 서버까지의 응답 시간과 실패 여부만 보냅니다. CPU와 메모리는 측정할 수 없습니다.

---

## 3. 폴더 구조

```
cusor-8bit/
├─ public/
│  └─ index.html            대시보드 전체 (HTML/CSS/JS 한 파일)
├─ src/
│  ├─ backend/
│  │  ├─ main.py            FastAPI 앱, 로그인, 장비/구역/연결/이벤트 API
│  │  ├─ ai_routes.py       AI 경보, 차단 명령, 에이전트 API, 백업/복구
│  │  ├─ agent_link.py      회원가입, 연결 코드, 탈퇴, 텔레메트리 API
│  │  ├─ models.py          ORM 모델 (일부 테이블)
│  │  ├─ database.py        DB 연결 설정
│  │  ├─ collector.py       PC 상태 수집기 (서버 API로 보고)
│  │  ├─ agent.py           프로세스 감시, 승인된 차단 실행
│  │  ├─ scanner.py         LAN 기기 탐색 (발표 중에는 끄기 권장)
│  │  └─ pinger.py          등록된 기기 핑 (노트북에서만 실행)
│  └─ ai/
│     └─ detector.py        Isolation Forest 기반 이상 탐지
├─ migrations/              운영 DB 변경 기록 (001, 002 실행 완료)
├─ schema.sql               빈 DB를 새로 만들 때만 사용 (운영 DB 재실행 금지)
├─ requirements.txt
├─ .env.example             환경변수 이름 목록 (값 없음)
└─ .gitignore               .env, backup/, 모델 파일 등 제외
```

---

## 4. 실행 방법

### 4-1. 서버 (Render)
- 저장소 `main` 브랜치에 push하면 자동 배포됩니다.
- Build Command: `pip install -r requirements.txt`
- Start Command: `PYTHONPATH=. uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
- 무료 플랜은 일정 시간 요청이 없으면 잠듭니다. 시연 전에 `https://cusor-8bit.onrender.com/api/health`를 열어 깨워 두세요.

### 4-2. 노트북 (관리자 PC, 로컬 실행)
```powershell
cd "저장소경로\src\backend"
python collector.py     # 이 PC의 CPU/메모리 측정
python agent.py         # 의심 프로세스 감시 (관리자 PowerShell 권장)
```
`.env`는 저장소 `src/backend/` 폴더에 두고, 값은 Render의 Environment 설정과 맞춥니다. 값은 채팅이나 저장소에 올리지 마세요.

### 4-3. 다른 PC 연결 (일반 사용자)
1. 웹에서 회원가입 (로그인 화면 → 회원가입)
2. 연결할 PC에 Python과 패키지 설치
   ```
   pip install psutil python-dotenv requests
   ```
3. PC 폴더에 `collector.py`와 `.env`를 둡니다. `.env`에는 두 줄만 있으면 됩니다.
   ```
   BACKEND_URL=https://cusor-8bit.onrender.com
   AGENT_API_KEY=(관리자에게 받은 값)
   ```
4. `python collector.py`를 실행하면 화면에 6자리 연결 코드가 뜹니다.
5. 웹에 로그인 → 사이드바 "내 PC 연결" → 코드 입력 → 연결
6. 연결이 끝나면 그 PC의 콘솔에 측정값이 5초마다 나옵니다. 같은 폴더의 `agent_id.txt`는 PC의 고유 ID이니 지우지 마세요.

---

## 5. 화면 사용법

| 메뉴 | 하는 일 |
|---|---|
| 대시보드 | 실시간 트래픽, 기기 현황, AI 위험 스코어, 최근 알림 요약 |
| 토폴로지 | 장비 연결 구조. 장비를 누르면 진단 창이 열림 |
| VLAN 구역 | 구역별로 장비만 모아서 보기 |
| 트래픽 · AI 분석 | 확대 차트, 장비별 부하 |
| 보안 로그 | 경보 기록, 엔드포인트 이벤트, 필터 |
| 기기 관리 | 기기 추가, 소유자 지정, 백업·복구 (관리자 전용 기능 포함) |
| 내 PC 연결 | 6자리 코드로 PC 연결, 내 PC 목록, 회원 탈퇴 |
| AI 가이드 | 사용법 질의응답, 팀 역할 |

### 권한
- **관리자**: 모든 장비와 구역을 봅니다. 기기 승인, 차단 승인, 백업·복구를 할 수 있습니다.
- **일반 사용자**: 본인이 연결한 PC만 봅니다. 가입 시 기본 구역(백본, 조회용) 권한이 함께 생성됩니다.

### 차단 흐름 (관리자 승인 기반)
1. `agent.py`가 감시 목록과 같은 이름의 프로세스를 찾으면 이벤트를 `detected`로 기록합니다. 이 시점에는 종료하지 않습니다.
2. AI가 이상 징후를 감지하면 경보가 만들어지고, 의심 프로세스 정보가 함께 연결됩니다.
3. 관리자가 대시보드에서 차단을 승인합니다.
4. `agent.py`가 명령을 받아서 PID, 이름, 생성 시각이 모두 일치할 때만 종료합니다. 결과는 서버에 보고됩니다.

시스템 프로세스(System, csrss.exe, explorer.exe 등)와 `agent.py` 자신은 종료 대상에서 제외됩니다.

---

## 6. 주요 API

인증이 필요한 API는 `Authorization: Bearer <토큰>` 헤더를 씁니다. 에이전트 API는 `X-API-Key` 헤더를 씁니다.

**사용자 / 인증**
| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/auth/login` | 로그인 (토큰 발급, 실패 10회 시 계정 1시간 잠김) |
| POST | `/api/auth/register` | 회원가입 (role=user 고정, 기본 구역 권한 부여) |
| GET | `/api/auth/me` | 내 정보 |
| DELETE | `/api/auth/me` | 회원 탈퇴 (비밀번호 확인, 관리자 불가, PC는 소유자만 해제) |
| POST | `/api/auth/validate-vlan` | 구역 코드 확인 후 토큰 재발급 |
| GET | `/api/auth/my-zones` | 내가 들어갈 수 있는 구역 |
| GET | `/api/users` | 사용자 목록 (관리자) |

**장비 / 구역 / 연결**
| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/devices` | 장비, 연결선, 구역 목록 (관리자: 전체, 일반: 본인 PC) |
| POST / PUT / DELETE | `/api/devices[/{id}]` | 장비 추가, 수정, 삭제 (관리자) |
| POST / DELETE | `/api/links` | 장비 연결선 추가, 삭제 |
| GET / POST / PUT / DELETE | `/api/vlans[/{id}]` | 구역 관리 |
| POST | `/api/link/claim` | 연결 코드로 PC를 내 계정에 연결 |

**텔레메트리 / 경보 / 이벤트**
| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/telemetry/latest` | 최근 측정값과 AI 위험 점수 (권한 범위 안) |
| GET | `/api/alerts` | 최근 알림 목록 |
| GET | `/api/endpoint-security/events` | 엔드포인트 이벤트 목록 |
| POST | `/api/endpoint-security/events` | 엔드포인트 이벤트 기록 (에이전트) |
| GET | `/api/ai/incidents` | AI 경보 목록 |
| POST | `/api/ai/train` | AI 기준선 학습 (관리자) |
| POST | `/api/ai/feedback` | 오탐 피드백 후 재학습 (관리자) |
| POST | `/api/security/block` | 차단 승인 (관리자) |

**에이전트 (X-API-Key)**
| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/agent/pair-request` | 연결 코드 발급 또는 연결 여부 확인 |
| POST | `/api/agent/telemetry` | PC 측정값 보고 |
| POST | `/api/agent/hello` | 기기 등록 확인 (IP 기준) |
| POST | `/api/agent/suspect` | 의심 프로세스 보고 |
| GET | `/api/agent/commands` | 승인된 차단 명령 가져오기 |
| POST | `/api/agent/commands/{id}/result` | 차단 결과 보고 |

**기기 등록 / 승인 / 상태**
| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/ai/register-request` | 브라우저 기기 등록 요청 |
| GET | `/api/ai/pending-devices` | 승인 대기 기기 (관리자) |
| POST | `/api/ai/enroll` | 기기 승인 (관리자) |
| POST | `/api/ai/heartbeat` | 브라우저 응답 시간 보고 (등록된 기기만) |
| GET | `/api/ai/connectivity` | 기기별 연결 상태 |
| POST | `/api/ai/connect-request` | 기기 간 연결 요청 |
| POST | `/api/ai/connect-respond` | 모바일 기기가 연결 요청에 응답 |

**백업 / 상태**
| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/admin/backup` | 백업 JSON 다운로드 (관리자) |
| POST | `/api/admin/restore` | 백업 복구 (관리자, `RESTORE` 문구 필요) |
| GET | `/api/health` | 서버 상태 확인 |

---

## 7. 환경변수 (이름만)

| 이름 | 어디서 쓰나 | 설명 |
|---|---|---|
| `DATABASE_URL` | 서버, 에이전트 | DB 접속 주소 (서버에만 두는 것을 원칙으로 함) |
| `JWT_SECRET` | 서버 | 로그인 토큰 서명 키 (필수) |
| `JWT_ALGORITHM` | 서버 | 기본 HS256 |
| `JWT_EXPIRE_MINUTES` | 서버 | 토큰 유효 시간, 기본 30분 |
| `AGENT_API_KEY` | 서버, 모든 에이전트 | 에이전트 인증 키 (필수) |
| `AUTO_ENROLL_VLAN` | 서버 | 설정하면 기기 등록이 승인 없이 바로 됨. 시연 승인 장면에서는 비움 |
| `AI_TRAIN_DEVICE_ID` | 서버 | AI 학습에 쓸 장비 ID. 비우면 전체 측정값으로 학습 |
| `DEFAULT_VLAN_ID` | 서버 | 연결된 PC와 가입 사용자의 기본 구역 ID (기본 1) |
| `BACKEND_URL` | 에이전트 | 서버 주소 |
| `COLLECT_DEVICE_NAME` | collector | PC 표시 이름 |
| `COLLECT_VLAN_ID` | collector (옛 방식) | 기본 구역 |
| `COLLECT_INTERVAL_SEC` | collector | 측정 주기, 기본 5초 |
| `PING_TARGET` | collector, pinger | 패킷 손실 측정 대상, 기본 8.8.8.8 |
| `SCAN_SUBNET` | scanner | 탐색 대역 (비우면 이 PC 기준 /24) |
| `IGNORE_IPS` | scanner | 팝업에서 제외할 IP 목록 |

---

## 8. 데이터베이스

- 테이블 11개와 뷰 1개: `users`, `vlans`, `devices`, `links`, `telemetry`, `alerts`, `alert_devices`, `user_vlans`, `endpoint_events`, `ai_incidents`, `ping_logs`, 뷰 `v_latest_telemetry`
- `migrations/001_client_uuid.sql`, `002_ping_logs.sql`은 운영 DB에 실행 완료되었습니다. 재실행하지 마세요.
- `schema.sql`은 맨 위에 `DROP TABLE`이 있어서 **운영 DB에 실행하면 모든 데이터가 지워집니다.** 빈 DB를 새로 만들 때만 사용하세요.
- 운영 DB 변경은 `migrations/` 파일로만 합니다. 실행 전에 백업을 먼저 받으세요.

---

## 9. 설계상 중요한 점

- **기기 식별**: 브라우저는 UUID를 만들어 `X-Device-Id`로 보냅니다. PC는 `agent_id.txt`의 ID를 씁니다. 같은 공인 IP를 쓰는 기기도 서로 구분됩니다.
- **측정 구분**: PC 측정값은 실제 값입니다. 스마트폰은 응답 시간만 측정하며, 화면에도 그렇게 표시합니다.
- **AI 위험 점수**: Isolation Forest로 CPU, 메모리, 트래픽, 지연, 손실을 봅니다. 현재 지연(ping) 값은 텔레메트리에 없어서 점수에 반영되지 않습니다. 실제 판단은 CPU, 메모리, 트래픽 중심입니다.
- **권한**: 관리자는 전체, 일반 사용자는 `devices.owner_id`가 본인인 장비만 봅니다.

---

## 10. 알려진 한계

1. **서버 메모리 상태**: 기기 승인 대기, 연결 코드, 차단 명령, 로그인 실패 기록은 서버 메모리에만 있습니다. 서버가 재시작되면 사라집니다. 서버는 워커 1개로 실행해야 합니다.
2. **무료 플랜**: Render 무료 플랜은 잠들 수 있어서 첫 요청이 느리거나 실패할 수 있습니다.
3. **공유 에이전트 키**: 모든 PC가 `AGENT_API_KEY` 하나를 씁니다. 키가 유출되면 모든 PC가 영향을 받습니다. PC별 키는 향후 과제입니다.
4. **로그인 잠금**: 실패 10회를 계정명 기준으로 셉니다. 같은 계정을 다른 사람이 악용해 잠글 수 있습니다.
5. **토큰 만료**: 토큰은 30분 뒤 만료됩니다. 만료되면 다시 로그인해야 합니다. 탈퇴한 사용자의 토큰도 만료 전까지 남지만, PC 연결 API는 사용자 존재를 확인합니다.
6. **백업 복구**: 복구하면 장비가 지워지면서 측정 기록(텔레메트리)도 함께 사라집니다.
7. **Windows 전용 스크립트**: `collector.py`, `agent.py`, `scanner.py`, `pinger.py`의 ping, arp 옵션은 Windows 기준입니다.
8. **다른 PC의 프로세스 감시**: 다른 PC에서 `agent.py`(프로세스 감시와 차단)는 아직 연결 코드 방식으로 바뀌지 않았습니다. 차단 기능은 노트북에서만 확실히 동작합니다.
9. **레거시 API**: `/api/devices/pending`, `/api/devices/enroll`, `/api/dashboard/overview`는 `devices.status` 컬럼을 쓰는데 현재 스키마에 없어서 호출하면 500이 납니다. 화면에서는 쓰지 않습니다.
10. **엔드포인트 이벤트 조회**: 현재 로그인한 모든 사용자가 전체 이벤트를 볼 수 있습니다. 관리자 전용으로 바꾸는 것이 좋습니다.

---

## 11. 보안 주의사항

- `.env`, `backup/`, `agent_id.txt`는 저장소에 올리지 않습니다. `.gitignore`에 있지만 이미 추적 중인 파일은 제외되지 않으니 `git ls-files`로 확인하세요.
- 비밀번호, 토큰, DB 주소를 캡처하거나 채팅에 붙여 넣지 마세요. 진단할 때는 값을 `***`로 가린 출력만 씁니다.
- 백업 파일(JSON, SQL)에는 계정 해시가 들어 있습니다. USB 같은 개인 매체에만 보관하세요.
- 과거 커밋에 `.env`나 `backup/` 파일이 남아 있을 수 있습니다. 저장소가 공개라면 발표 후에 기록을 정리하는 것을 권합니다.

---

## 12. 발표 전 확인 목록

- [ ] Render에서 새 배포가 성공했는지, 로그에 시작 에러가 없는지
- [ ] `https://cusor-8bit.onrender.com/api/health` 응답
- [ ] 회원가입 → 로그인 → 구역 선택 → 대시보드 진입
- [ ] 새 PC 연결 (collector 실행 → 코드 입력 → 측정값 표시)
- [ ] 일반 사용자 계정에서는 본인 PC만 보이는지
- [ ] 관리자 계정에서 전체 장비가 보이는지
- [ ] 차단 시나리오 (backdoor.exe 탐지 → 승인 → 종료)
- [ ] 노트북 절전 모드 해제, `AUTO_ENROLL_VLAN` 비어 있음 확인
- [ ] 시연 전에 `Ctrl+F5`로 새로고침하고, 필요하면 다시 로그인
