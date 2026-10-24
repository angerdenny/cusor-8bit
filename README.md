# 8bit AI Pulse · AI 기반 네트워크 관제 시스템

네트워크 장비와 PC의 상태(CPU, 메모리, 트래픽, 응답 시간)를 한 화면에서 보고, AI로 장애 위험을 예측하며, 관리자가 승인한 보안 차단을 실행하는 관제 시스템입니다.

- 서버와 대시보드: https://cusor-8bit.onrender.com
- 데이터베이스: Aiven MySQL 8.0

> 줄 번호는 현재 저장소 파일 기준입니다. 코드를 수정하면 줄 번호가 바뀌니 함수 이름으로 검색하세요.

---

## 목차

1. [팀 역할](#1-팀-역할)
2. [사용 언어와 기술](#2-사용-언어와-기술)
3. [전체 구성](#3-전체-구성)
4. [폴더 구조](#4-폴더-구조)
5. [실행 방법](#5-실행-방법)
6. [화면 사용법](#6-화면-사용법)
7. [상세 문서](#7-상세-문서)

---

## 1. 팀 역할

PPT "역할분담 (개발 조직과 책임 구분)" 기준입니다.

| 구분 | 역할 | 담당자 | 주요 업무 |
|---|---|---|---|
| I | 프로젝트 총괄 및 통합 | 이지환 (팀장) | 전체 진행 관리, 백엔드 API·AI 모델·UI 간 데이터 연동 검증, 소스코드 최종 통합 검수 |
| II | 시스템 백엔드 및 통합관제 개발 | 구본학 | 연동 API와 경보 로직 개발, 실시간 데이터 연동 API 구축, 장애 경보 알림 |
| II | 〃 | 장우진 | 통합관제 화면과 UI 구현, 실시간 관제 대시보드, 상태 맵 시각화, 발표자료(PPT) 총괄 |
| III | 네트워크 및 데이터 수집 | 양이수 | 인프라와 장애 시나리오 설계, 네트워크 구성도(토폴로지) 구축 |
| III | 〃 | 김범수 | 로그 수집 모듈 개발, 장비 상태 로그 자동 수집 스크립트, 포스터 시각화 자료 |
| IV | 데이터 베이스 및 인공지능 분석 | 김민석 | 데이터 구조와 파이프라인 구축, 관제 DB 설계, 데이터 정규화, 수집 파이프라인(ETL) |
| IV | 〃 | 최민규 | 인공지능 이상 탐지 모델 설계, 장애 예측 머신러닝 알고리즘 설계, 학습 데이터셋 가공 |
| IV | 〃 | 김태현 | 모델 최적화, 학습 포스터 제작, 알고리즘 성능 평가, AI 예측 결과 DB 연동 |
| IV | 〃 | 박동연 | 실시간 AI 추론 API와 트래픽 제어 로직 개발, 예측 결과 기반 동적 트래픽 분산 제어, 모델 응답 속도 최적화, 시뮬레이션 검증 |

> 표의 담당자는 PPT 기준입니다. 실제로 누가 어떤 코드를 썼는지는 아래 명령으로 확인할 수 있습니다.
> ```
> git shortlog -sn
> git log --format="%an | %s" -- src/backend/ai_routes.py
> ```

---

## 2. 사용 언어와 기술

| 영역 | 언어 · 기술 | 쓰는 곳 |
|---|---|---|
| 서버 | Python, FastAPI, SQLAlchemy, PyMySQL | `src/backend/main.py`, `ai_routes.py`, `agent_link.py` |
| 인증 | python-jose (JWT), passlib + bcrypt | `main.py` |
| 에이전트 | Python, psutil, requests | `collector.py`, `agent.py`, `scanner.py`, `pinger.py` |
| AI | scikit-learn (Isolation Forest), numpy, joblib | `src/ai/detector.py` |
| 화면 | HTML, CSS (Tailwind CSS CDN), JavaScript | `public/index.html` |
| 아이콘 | lucide | `public/index.html` |
| 데이터베이스 | MySQL 8.0 | `schema.sql`, `migrations/` |
| 배포 | Render (Build: `pip install -r requirements.txt`) | 서버 설정 |

---

## 3. 전체 구성

```
  다른 PC ─── collector.py ───┐
  노트북 ──── collector.py ───┤
              agent.py ───────┤  (AGENT_API_KEY, 서버 API로만 보고)
              scanner.py ─────┤
              pinger.py ──────┤
                              ▼
  브라우저 ─── 대시보드 ──── FastAPI 서버 (Render) ──── MySQL (Aiven)
  아이패드 ─── 응답 시간 보고 ─┘
```

- 서버만 DB에 접속합니다. 다른 PC는 DB 주소와 비밀번호를 갖지 않습니다.
- PC는 CPU, 메모리, 트래픽, 패킷 손실을 실제로 측정합니다.
- 스마트폰과 아이패드는 서버까지의 응답 시간과 실패 여부만 측정합니다. CPU와 메모리는 브라우저에서 읽을 수 없습니다.

---

## 4. 폴더 구조

```
cusor-8bit/
├─ public/
│  └─ index.html          대시보드 화면 (HTML, CSS, JavaScript 한 파일)
├─ src/
│  ├─ backend/
│  │  ├─ main.py          서버 시작, 로그인, 장비·구역·연결·이벤트 API (Python)
│  │  ├─ ai_routes.py     AI 경보, 차단 승인, 에이전트 API, 백업·복구 (Python)
│  │  ├─ agent_link.py    회원가입, PC 연결 코드, 탈퇴, 측정값 API (Python)
│  │  ├─ models.py        ORM 모델 (Python, SQLAlchemy)
│  │  ├─ database.py      DB 연결 설정 (Python)
│  │  ├─ collector.py     PC 상태 측정 후 서버 전송 (Python)
│  │  ├─ agent.py         의심 프로세스 탐지, 승인된 차단 실행 (Python)
│  │  ├─ scanner.py       같은 네트워크의 기기 탐색 (Python, Windows 명령 사용)
│  │  └─ pinger.py        등록된 기기 핑 측정 (Python, Windows 명령 사용)
│  └─ ai/
│     └─ detector.py      이상 탐지 모델 (Python, scikit-learn)
├─ migrations/
│  ├─ 001_client_uuid.sql    기기 식별자 컬럼 추가 (SQL)
│  └─ 002_ping_logs.sql      응답 시간 기록 테이블 (SQL)
├─ schema.sql             전체 테이블 생성 (SQL)
├─ requirements.txt       Python 패키지 목록
├─ .env.example           환경변수 이름 목록 (값 없음)
└─ .gitignore             .env, backup/, agent_id.txt 등 제외
```

---

## 5. 실행 방법

### 5-1. 서버 (Render)
- `main` 브랜치에 push하면 자동 배포됩니다.
- Build Command: `pip install -r requirements.txt`
- Start Command: `PYTHONPATH=. uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
- 상태 확인: `https://cusor-8bit.onrender.com/api/health`

### 5-2. 노트북 (로컬 측정과 감시)
```powershell
cd "저장소경로\src\backend"
python collector.py     # 이 PC의 CPU, 메모리 측정
python agent.py         # 의심 프로세스 감시 (관리자 PowerShell 권장)
```
`.env`는 `src/backend/` 폴더에 두고, 값은 Render의 Environment 설정과 맞춥니다. 값을 저장소나 채팅에 올리지 마세요.

### 5-3. 다른 PC 연결 (일반 사용자)
1. 로그인 화면에서 회원가입
2. 연결할 PC에 패키지 설치
   ```
   pip install psutil python-dotenv requests
   ```
3. PC 폴더에 `collector.py`와 `.env`를 둡니다. `.env`는 두 줄입니다.
   ```
   BACKEND_URL=https://cusor-8bit.onrender.com
   AGENT_API_KEY=(관리자에게 받은 값)
   ```
4. `python collector.py` 실행 → 화면에 6자리 코드 표시
5. 웹 로그인 → 사이드바 "내 PC 연결" → 코드 입력
6. 연결 후 콘솔에 측정값이 5초마다 표시됩니다. `agent_id.txt`는 PC 고유 ID이므로 삭제하지 마세요.

---

## 6. 화면 사용법

| 메뉴 | 내용 |
|---|---|
| 대시보드 | 실시간 트래픽, 기기 현황, AI 위험 점수, 최근 알림 |
| 네트워크 토폴로지 | 장비 연결 구조. 장비를 누르면 진단 창이 열림 |
| VLAN 구역 | 구역별 장비만 보기 |
| 트래픽 · AI 분석 | 확대 차트, 장비별 부하 |
| 보안 로그 | 경보 기록, 엔드포인트 이벤트, 필터 |
| 기기 관리 | 기기 추가, 소유자 지정, 백업·복구 |
| 내 PC 연결 | 연결 코드 입력, 내 PC 목록, 회원 탈퇴 |
| AI 가이드 | 사용법 질의응답, 팀 역할 |

### 권한
- **관리자**: 모든 장비와 구역 조회, 기기 승인, 차단 승인, 백업·복구
- **일반 사용자**: 본인이 연결한 PC만 조회. 가입 시 기본 구역(백본, 조회용) 권한이 함께 생성됩니다.

### 차단 흐름
1. `agent.py`가 감시 목록과 이름이 정확히 같은 프로세스를 찾으면 `detected`로 기록합니다. 이때는 종료하지 않습니다.
2. AI가 이상을 감지하면 경보가 만들어지고, 의심 프로세스 정보가 함께 연결됩니다.
3. 관리자가 대시보드에서 차단을 승인합니다.
4. `agent.py`가 명령을 받아 PID, 이름, 생성 시각이 모두 맞을 때만 종료하고 결과를 보고합니다.

---

## 7. 상세 문서

<details>
<summary><b>7-1. 프로젝트 총괄 및 통합 — 이지환 (팀장)</b></summary>

**담당 업무 (PPT 기준)**
- 전체 프로젝트 진행 상황 관리, 팀원 개발 현황 점검
- 백엔드 API, AI 모델, UI 간 데이터 연동 검증
- 소스코드 최종 통합 검수

**구현 범위 (코드)**: 로그인, 권한 판단, 회원가입, PC 연결, 회원 탈퇴

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/main.py` | Python | L71–L72 | 로그인 실패 잠금 설정 (10회, 1시간) |
| `src/backend/main.py` | Python | L138 | `get_current_user` 토큰 검사 |
| `src/backend/main.py` | Python | L165 | `require_admin` 관리자 검사 |
| `src/backend/main.py` | Python | L175–L216 | `/api/auth/login` 로그인 |
| `src/backend/main.py` | Python | L551–L552 | 일반 사용자 장비 목록을 본인 PC로 거르는 부분 |
| `src/backend/agent_link.py` | Python | L66 | `/api/auth/register` 회원가입 |
| `src/backend/agent_link.py` | Python | L117 | `/api/link/claim` 연결 코드 확인 |
| `src/backend/agent_link.py` | Python | L150–L164 | `/api/auth/me` (DELETE) 회원 탈퇴 |
| `src/backend/ai_routes.py` | Python | L125 | `visible_device_ids` 장비 조회 범위 계산 |

**핵심 코드**

장비 목록 권한 (`main.py`, L551–L552):
```python
if current_user.get("role") != "admin":
    device_rows = [r for r in device_rows if r.owner_id == current_user["user_id"]]
```

회원 탈퇴 (`agent_link.py`):
```python
if current_user.get("role") == "admin":
    raise HTTPException(status_code=403, detail="관리자 계정은 탈퇴할 수 없습니다")
...
if not pwd_context.verify(body.password, row.password_hash):
    raise HTTPException(status_code=400, detail="비밀번호가 올바르지 않습니다")
db.execute(text("DELETE FROM users WHERE id=:u"), {"u": uid})
```

</details>

<details>
<summary><b>7-2. 시스템 백엔드 및 통합관제 개발 — 장우진</b></summary>

**담당 업무 (PPT 기준)**
- 통합관제 화면과 UI 구현
- 실시간 관제 대시보드 화면 구현
- 상태 맵 시각화
- 발표자료(PPT) 총괄 제작 (코드 아님)

**구현 범위 (코드)**: 대시보드 카드, 알림 표시, 서버 호출 공통 함수

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | HTML | L2595 | 대시보드 섹션 시작 |
| `public/index.html` | HTML | L2598 | 실시간 수신 트래픽 카드 (`traffic-card`) |
| `public/index.html` | HTML | L2686 | 최근 알림 칸 (`alert-mini`) |
| `public/index.html` | JavaScript | L3447 | `apiFetch` 토큰 첨부, 401이면 로그아웃 |
| `public/index.html` | JavaScript | L5529 | `renderAlerts` 알림 목록 그리기 |
| `public/index.html` | JavaScript | L4005 | `switchView` 화면 전환 |

**핵심 코드**

서버 호출 공통 함수 (`index.html`, `apiFetch`):
```javascript
async function apiFetch(url, options = {}) {
    const token = sessionStorage.getItem('token');
    const headers = { ...(options.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) { logout(); throw new Error('세션이 만료되었습니다'); }
    return res;
}
```

최근 알림 칸 (`renderAlerts`):
```javascript
const mini = document.getElementById('alert-mini');
if (mini) mini.innerHTML = alertList.length ? alertList.slice(0, 5).map(alertHtml).join('') : /* 빈 안내 */;
```

</details>

<details>
<summary><b>7-3. 네트워크 및 데이터 수집 — 양이수</b></summary>

**담당 업무 (PPT 기준)**
- 인프라 및 장애 시나리오 설계
- 네트워크 구성도(토폴로지) 구축

**구현 범위 (코드)**: 토폴로지 노드 배치, 연결선, 구역 영역, 확대와 이동

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | JavaScript | L3819 | `SIM_TYPES` 장애 시나리오 정의 (DDoS, 패킷 손실 등) |
| `public/index.html` | HTML | L2659 | 장애 시뮬레이션 패널 |

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | HTML | L2701 | 토폴로지 섹션 시작 |
| `public/index.html` | JavaScript | L3764 | `EDGES` 기본 연결 목록 |
| `public/index.html` | JavaScript | L3766 | `edgeId` 연결선 ID 만들기 |
| `public/index.html` | JavaScript | L4313 | `buildNodeUI` 노드 화면 만들기 |
| `public/index.html` | JavaScript | L4385 | `onTopoPointerDown` 드래그 시작 |
| `public/index.html` | JavaScript | L4469 | `computeTopoGraph` 그래프 계산 |
| `public/index.html` | JavaScript | L4522 | `layoutTiers` 계층 배치 |
| `public/index.html` | JavaScript | L4115 | `renderVlanView` 구역 화면 그리기 |
| `src/backend/main.py` | Python | L742 | `/api/links` 연결선 추가 |
| `src/backend/main.py` | Python | L785 | `/api/links` 연결선 삭제 |

**핵심 코드**

연결선 ID (`index.html`, `edgeId`):
```javascript
function edgeId(a, b) { return `ln-${a}__${b}`; }
```

</details>

<details>
<summary><b>7-4. 네트워크 및 데이터 수집 — 김범수</b></summary>

**담당 업무 (PPT 기준)**
- 로그 수집 모듈 개발
- 장비 상태 로그 자동 수집 스크립트 개발
- 포스터 시각화 자료 제작 (코드 아님)

**구현 범위 (코드)**: PC 측정과 전송, 기기 탐색, 프로세스 감시, 기기 핑

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/collector.py` | Python | L37 | `load_agent_id` PC 고유 ID 만들기·읽기 |
| `src/backend/collector.py` | Python | L57 | `measure_packet_loss` 패킷 손실 측정 |
| `src/backend/collector.py` | Python | L70 | `wait_for_link` 연결 코드 표시와 연결 대기 |
| `src/backend/collector.py` | Python | L95 | `main` 측정 루프 |
| `src/backend/collector.py` | Python | L110 | 수신 트래픽 계산 (Mbps) |
| `agent.py` | Python | L32 | `SUSPICIOUS_NAMES` 감시 목록 |
| `agent.py` | Python | L35 | `PROTECTED_NAMES` 종료 제외 목록 |
| `agent.py` | Python | L88 | `scan_suspicious` 의심 프로세스 찾기 |
| `agent.py` | Python | L103 | `report_suspicious` 탐지 기록과 의심 정보 전송 |
| `agent.py` | Python | L126 | `try_kill` 승인된 명령 실행 (PID, 이름, 생성 시각 확인) |
| `agent.py` | Python | L164 | `poll_commands` 차단 명령 가져오기 |
| `scanner.py` | Python | L26 | `ARP_RE` ARP 표 해석 정규식 |
| `scanner.py` | Python | L49 | `arp_hosts` 같은 대역의 기기 찾기 |
| `scanner.py` | Python | L75 | `scan_once` 핑 후 ARP 표 읽기 |
| `pinger.py` | Python | L17 | `ping` 핑 한 번 보내기 |
| `pinger.py` | Python | L35 | `main` 등록된 기기 핑 루프 |

**핵심 코드**

수신 트래픽 계산 (`collector.py`, L110):
```python
traffic_in = round((net.bytes_recv - last.bytes_recv) * 8 / elapsed / 1_000_000, 3)
```

ARP 표 해석 (`scanner.py`, L26):
```python
ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")
```

</details>

<details>
<summary><b>7-5. 시스템 백엔드 및 통합관제 개발 — 구본학</b></summary>

**담당 업무 (PPT 기준)**
- 연동 API와 경보 로직 개발
- 실시간 데이터 연동 API 구축
- 장애 경보 알림

**구현 범위 (코드)**: AI 경보 생성, 차단 승인과 명령 전달, 에이전트 API, 기기 등록 요청

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L37 | `SUSPECT_TTL` 오래된 의심 보고 무시 기준 (60초) |
| `src/backend/ai_routes.py` | Python | L120 | `add_alert` 경보 기록 추가 |
| `src/backend/ai_routes.py` | Python | L169 | `score_rows` 측정값에 위험 점수 붙이기 |
| `src/backend/ai_routes.py` | Python | L210 | `build_ai_router` 라우터 묶음 생성 |
| `src/backend/ai_routes.py` | Python | L213 | `agent_auth` 에이전트 키 검사 |
| `src/backend/ai_routes.py` | Python | L239 | `/api/security/block` 차단 승인 |
| `src/backend/ai_routes.py` | Python | L278–L300 | 에이전트 `hello`, `suspect`, `commands`, 결과 보고 |
| `src/backend/ai_routes.py` | Python | L354 | `/api/ai/register-request` 기기 등록 요청 |
| `src/backend/ai_routes.py` | Python | L392 | `/api/ai/heartbeat` 응답 시간 기록 (등록된 기기만) |
| `src/backend/main.py` | Python | L829 | `/api/alerts` 알림 목록 |
| `src/backend/main.py` | Python | L838–L890 | 엔드포인트 이벤트 조회·기록 |

**핵심 코드**

의심 보고 유효 시간 (`ai_routes.py`, L37):
```python
SUSPECT_TTL = 60  # 초. 이보다 오래된 의심 프로세스 보고는 무시
```

차단 명령 전달 (`ai_routes.py`, L295):
```python
@r.get("/api/agent/commands", dependencies=[Depends(agent_auth)])
def poll_commands(device_id: int):
```

</details>

<details>
<summary><b>7-6. 데이터 베이스 및 인공지능 분석 — 김민석</b></summary>

**담당 업무 (PPT 기준)**
- 데이터 구조 및 파이프라인 구축
- 관제 DB 설계
- 데이터 정규화와 수집 파이프라인(ETL) 구축

**구현 범위 (코드)**: 테이블 설계, 마이그레이션, ORM 모델, DB 연결, 백업·복구

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `schema.sql` | SQL | L9 | 기존 테이블 삭제 (운영 DB에 실행하면 데이터가 지워짐) |
| `schema.sql` | SQL | L25 | `users` 테이블 |
| `schema.sql` | SQL | L57 | `devices` 테이블 (좌표 제약 포함) |
| `schema.sql` | SQL | L108 | `telemetry` 테이블 (측정값) |
| `schema.sql` | SQL | L132 | `alerts` 테이블 (알림) |
| `schema.sql` | SQL | L196 | `user_vlans` 테이블 (구역 권한) |
| `schema.sql` | SQL | L212 | `endpoint_events` 테이블 (보안 이벤트) |
| `schema.sql` | SQL | L225 | `v_latest_telemetry` 뷰 (장비별 최신 측정값) |
| `schema.sql` | SQL | L256 | `ai_incidents` 테이블 (AI 경보) |
| `schema.sql` | SQL | L271 | `ping_logs` 테이블 (응답 시간) |
| `migrations/001_client_uuid.sql` | SQL | 전체 | `devices.client_uuid` 추가, 인덱스 변경 |
| `migrations/002_ping_logs.sql` | SQL | 전체 | `ping_logs` 생성 (여러 번 실행해도 안전) |
| `src/backend/models.py` | Python | L13–L82 | ORM 모델 (User, Vlan, Device, Telemetry, Alert 등) |
| `src/backend/database.py` | Python | L17 | `get_db` 요청마다 DB 세션 열고 닫기 |
| `src/backend/ai_routes.py` | Python | L413 | `/api/admin/backup` 백업 내보내기 |
| `src/backend/ai_routes.py` | Python | L434 | `/api/admin/restore` 백업 복구 |

**핵심 코드**

사용자 테이블 (`schema.sql`, L25):
```sql
CREATE TABLE users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(50)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(10)  NOT NULL DEFAULT 'user',
```

DB 세션 (`database.py`, L17):
```python
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

</details>

<details>
<summary><b>7-7. 데이터 베이스 및 인공지능 분석 — 최민규, 김태현</b></summary>

**담당 업무 (PPT 기준)**
- 최민규: 인공지능 이상 탐지 모델 설계, 장애 예측 머신러닝 알고리즘 설계, 학습 데이터셋 가공
- 김태현: 모델 최적화, 알고리즘 성능 평가, AI 예측 결과 DB 연동, 학습 포스터 제작 (코드 아님)

**구현 범위 (코드)**: 이상 탐지 모델 학습, 위험 점수 계산, 오탐 재학습

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L197 | `ai_incidents` 테이블에 AI 예측 결과 저장 (AI 예측 결과 DB 연동) |

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/ai/detector.py` | Python | L22 | `NetworkAnomalyDetector` 클래스 |
| `src/ai/detector.py` | Python | L40 | `train_baseline` 정상 기준선 학습 |
| `src/ai/detector.py` | Python | L58 | `predict_risk` 위험 점수 계산 |
| `src/ai/detector.py` | Python | L70 | 점수 공식 (0–100) |
| `src/ai/detector.py` | Python | L77 | `add_feedback` 오탐 샘플로 재학습 |
| `src/backend/ai_routes.py` | Python | L30 | `train_query` 학습 데이터 조회 (`AI_TRAIN_DEVICE_ID` 사용) |
| `src/backend/ai_routes.py` | Python | L169 | `score_rows` 측정값마다 위험 점수 붙이기 |
| `src/backend/ai_routes.py` | Python | L229 | `/api/ai/train` 재학습 (관리자) |
| `src/backend/ai_routes.py` | Python | L259 | `/api/ai/feedback` 오탐 피드백 (관리자) |

**핵심 코드**

위험 점수 공식 (`detector.py`, L70):
```python
risk = 100.0 / (1.0 + np.exp(np.clip(SENSITIVITY * d, -50, 50)))
```
- `d`는 모델의 판정 값입니다. 양수는 정상, 음수는 이상입니다.
- 점수가 `ANOMALY_THRESHOLD`(60) 이상이면 이상으로 봅니다.

**알려진 제약**: 지연(ping) 특성은 현재 측정값에 없어서 항상 0입니다. 실제 점수는 CPU, 메모리, 트래픽 중심입니다.

</details>

<details>
<summary><b>7-8. 데이터 베이스 및 인공지능 분석 — 박동연</b></summary>

**담당 업무 (PPT 기준)**
- 실시간 AI 추론 API와 트래픽 제어 로직 개발
- 예측 결과 기반 동적 트래픽 분산 제어
- 모델 응답 속도 최적화 및 시뮬레이션 검증

**구현 범위 (코드)**: 추론 호출과 트래픽 관련 처리 (담당 파일 확인 필요)

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L180 | `predict_risk` 추론 호출 (위험 점수 계산) |
| `src/backend/ai_routes.py` | Python | L265–L275 | 오탐 피드백 전후 위험 점수 비교 |
| `src/backend/collector.py` | Python | L110 | 수신 트래픽 계산 (Mbps) |

</details>

<details>
<summary><b>8. 전체 API 목록</b></summary>

인증이 필요한 API는 `Authorization: Bearer <토큰>` 헤더를 씁니다. 에이전트 API는 `X-API-Key` 헤더를 씁니다.

**사용자 · 인증**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| POST | `/api/auth/login` | main.py : 175 | 로그인 (실패 10회 시 1시간 잠금) |
| GET | `/api/auth/me` | main.py : 218 | 내 정보 |
| DELETE | `/api/auth/me` | agent_link.py : 150 | 회원 탈퇴 |
| POST | `/api/auth/register` | agent_link.py : 66 | 회원가입 |
| POST | `/api/auth/validate-vlan` | main.py : 248 | 구역 코드 확인 후 토큰 재발급 |
| GET | `/api/auth/my-zones` | main.py : 295 | 들어갈 수 있는 구역 목록 |
| GET | `/api/users` | main.py : 570 | 사용자 목록 |

**장비 · 구역 · 연결**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/devices` | main.py : 512 | 장비, 연결선, 구역 목록 |
| POST | `/api/devices` | main.py : 630 | 장비 추가 (관리자) |
| PUT | `/api/devices/{id}` | main.py : 663 | 장비 수정 (관리자) |
| DELETE | `/api/devices/{id}` | main.py : 714 | 장비 삭제 (관리자) |
| POST | `/api/links` | main.py : 742 | 연결선 추가 |
| DELETE | `/api/links` | main.py : 785 | 연결선 삭제 |
| GET | `/api/vlans` | main.py : 587 | 구역 목록 |
| POST | `/api/vlans` | main.py : 593 | 구역 추가 (관리자) |
| PUT | `/api/vlans/{id}` | main.py : 607 | 구역 수정 (관리자) |
| DELETE | `/api/vlans/{id}` | main.py : 620 | 구역 삭제 (관리자) |
| POST | `/api/link/claim` | agent_link.py : 116 | 연결 코드로 PC 연결 |

**측정 · 경보 · 이벤트**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/telemetry/latest` | main.py : 809 | 최근 측정값과 위험 점수 |
| GET | `/api/alerts` | main.py : 828 | 알림 목록 |
| GET | `/api/ai/incidents` | ai_routes.py : 218 | AI 경보 목록 |
| POST | `/api/ai/train` | ai_routes.py : 229 | 기준선 재학습 (관리자) |
| POST | `/api/security/block` | ai_routes.py : 238 | 차단 승인 (관리자) |
| POST | `/api/ai/feedback` | ai_routes.py : 259 | 오탐 피드백 (관리자) |
| GET | `/api/endpoint-security/events` | main.py : 838 | 엔드포인트 이벤트 목록 |
| POST | `/api/endpoint-security/events` | main.py : 858 | 엔드포인트 이벤트 기록 (에이전트) |

**기기 등록 · 상태 · 연결 요청**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| POST | `/api/ai/register-request` | ai_routes.py : 353 | 브라우저 기기 등록 요청 |
| GET | `/api/ai/pending-devices` | ai_routes.py : 308 | 승인 대기 기기 (관리자) |
| POST | `/api/ai/enroll` | ai_routes.py : 312 | 기기 승인 (관리자) |
| POST | `/api/ai/heartbeat` | ai_routes.py : 391 | 응답 시간 보고 |
| GET | `/api/ai/connectivity` | ai_routes.py : 544 | 기기별 연결 상태 |
| POST | `/api/ai/connect-request` | ai_routes.py : 492 | 기기 간 연결 요청 (관리자) |
| GET | `/api/ai/my-connect-request` | ai_routes.py : 510 | 나에게 온 연결 요청 |
| POST | `/api/ai/connect-respond` | ai_routes.py : 519 | 연결 요청 응답 |

**에이전트 (X-API-Key)**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| POST | `/api/agent/pair-request` | agent_link.py : 96 | 연결 코드 발급 또는 연결 여부 확인 |
| POST | `/api/agent/telemetry` | agent_link.py : 166 | PC 측정값 보고 |
| POST | `/api/agent/hello` | ai_routes.py : 278 | 기기 등록 확인 |
| POST | `/api/agent/suspect` | ai_routes.py : 289 | 의심 프로세스 보고 |
| GET | `/api/agent/commands` | ai_routes.py : 294 | 승인된 차단 명령 가져오기 |
| POST | `/api/agent/commands/{id}/result` | ai_routes.py : 299 | 차단 결과 보고 |

**백업 · 상태**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/admin/backup` | ai_routes.py : 412 | 백업 JSON 다운로드 (관리자) |
| POST | `/api/admin/restore` | ai_routes.py : 433 | 백업 복구 (`RESTORE` 입력 필요) |
| GET | `/api/health` | main.py : 890 | 서버 상태 |
| GET | `/api/admin/db-test` | main.py : 896 | DB 연결 확인 (관리자) |

</details>

<details>
<summary><b>9. 환경변수 (이름과 설명)</b></summary>

| 이름 | 쓰는 곳 | 설명 |
|---|---|---|
| `DATABASE_URL` | 서버 | DB 접속 주소 |
| `JWT_SECRET` | 서버 | 로그인 토큰 서명 키 (필수) |
| `JWT_ALGORITHM` | 서버 | 토큰 알고리즘, 기본 HS256 |
| `JWT_EXPIRE_MINUTES` | 서버 | 토큰 유효 시간, 기본 30분 |
| `AGENT_API_KEY` | 서버, 에이전트 | 에이전트 인증 키 (필수) |
| `AUTO_ENROLL_VLAN` | 서버 | 설정하면 기기 등록을 승인 없이 바로 처리 |
| `AI_TRAIN_DEVICE_ID` | 서버 | AI 학습에 쓸 장비 ID, 비우면 전체 측정값 사용 |
| `DEFAULT_VLAN_ID` | 서버 | 새 PC와 가입 사용자의 기본 구역 ID, 기본 1 |
| `BACKEND_URL` | 에이전트 | 서버 주소 |
| `COLLECT_DEVICE_NAME` | collector | PC 표시 이름 |
| `COLLECT_INTERVAL_SEC` | collector | 측정 주기, 기본 5초 |
| `PING_TARGET` | collector, pinger | 패킷 손실 측정 대상, 기본 8.8.8.8 |
| `SCAN_SUBNET` | scanner | 탐색 대역, 비우면 이 PC 기준 /24 |
| `IGNORE_IPS` | scanner | 탐색 결과에서 제외할 IP 목록 |

</details>

<details>
<summary><b>10. 데이터베이스 테이블</b></summary>

| 테이블 | 역할 | 주요 컬럼 |
|---|---|---|
| `users` | 사용자 계정 | username, password_hash, role (admin / user) |
| `vlans` | 구역 | code, name, cidr, color |
| `devices` | 장비 (PC, 기기) | name, ip, type, owner_id, x, y, client_uuid, vlan_id |
| `links` | 장비 간 연결선 | source_id, target_id |
| `telemetry` | 측정값 | device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss |
| `alerts` | 알림 | lv, title, msg, cause, action |
| `alert_devices` | 알림과 장비 연결 | alert_id, device_id |
| `user_vlans` | 사용자별 구역 권한 | user_id, vlan_id, access_level |
| `endpoint_events` | 엔드포인트 보안 이벤트 | action, process_name, pid, reason |
| `ai_incidents` | AI 경보 | device_id, risk_score, status, process_name, pid |
| `ping_logs` | 응답 시간 기록 | device_id, ok, rtt_ms |
| 뷰 `v_latest_telemetry` | 장비별 최신 측정값 1건 | |

**DB 변경 규칙**
- 운영 DB 변경은 `migrations/` 파일로만 합니다. 실행 전에 백업을 받습니다.
- `schema.sql`은 맨 위에 `DROP TABLE`이 있어서 운영 DB에 실행하면 모든 데이터가 지워집니다.

</details>

<details>
<summary><b>11. 설계 핵심</b></summary>

**기기 식별**
- 브라우저는 UUID를 만들어 `X-Device-Id` 헤더로 보냅니다.
- PC는 `agent_id.txt`의 ID를 씁니다. 두 값 모두 `devices.client_uuid`에 저장됩니다.
- 같은 공인 IP를 쓰는 기기도 서로 구분됩니다.

**측정 구분**
- PC: 실제 CPU, 메모리, 트래픽, 패킷 손실
- 스마트폰, 아이패드: 서버까지의 응답 시간과 실패 여부만

**권한**
- 관리자: 모든 장비
- 일반 사용자: `devices.owner_id`가 본인인 장비만

**연결 코드**
- 서버 메모리에 보관하고 10분 뒤 만료합니다.
- 한 번 사용하면 삭제합니다.

**회원 탈퇴**
- 계정과 구역 권한은 삭제합니다.
- 연결된 PC는 삭제하지 않고 소유자만 비웁니다. 이후 다시 연결할 수 있습니다.

</details>

<details>
<summary><b>12. 알려진 한계</b></summary>

1. **서버 메모리 상태**: 기기 승인 대기, 연결 코드, 차단 명령, 로그인 실패 기록은 서버 메모리에만 있습니다. 서버가 재시작되면 사라집니다. 워커는 1개로 실행해야 합니다.
2. **무료 플랜**: Render 무료 플랜은 잠들 수 있어서 첫 요청이 느리거나 실패할 수 있습니다.
3. **공유 에이전트 키**: 모든 PC가 `AGENT_API_KEY` 하나를 씁니다. PC마다 키를 나누는 것은 향후 과제입니다.
4. **로그인 잠금**: 실패 횟수를 계정명 기준으로 셉니다. 다른 사람이 같은 계정을 잠글 수 있습니다.
5. **토큰 만료**: 토큰은 30분 뒤 만료됩니다. 탈퇴한 사용자의 토큰은 만료 전까지 남지만, PC 연결 API에서 계정 존재 여부를 확인합니다.
6. **백업 복구**: 복구하면 장비가 지워지면서 측정 기록도 함께 사라집니다.
7. **Windows 명령 사용**: `collector.py`, `agent.py`, `scanner.py`, `pinger.py`의 ping, arp 옵션은 Windows 기준입니다.
8. **다른 PC의 차단**: `agent.py`의 차단 실행은 노트북에서 확인되었습니다. 다른 PC에서는 아직 연결 코드 방식으로 바뀌지 않았습니다.
9. **레거시 API**: `/api/devices/pending`, `/api/devices/enroll`, `/api/dashboard/overview`는 `devices.status` 컬럼을 사용하는데 현재 스키마에 없어서 호출하면 500이 납니다. 화면에서는 호출하지 않습니다.
10. **엔드포인트 이벤트 조회**: 로그인한 모든 사용자가 전체 이벤트를 볼 수 있습니다. 관리자 전용으로 바꾸는 것이 좋습니다.

</details>

<details>
<summary><b>13. 보안 주의사항</b></summary>

- `.env`, `backup/`, `agent_id.txt`는 저장소에 올리지 않습니다. `.gitignore`에 있어도 이미 추적 중인 파일은 제외되지 않으니 `git ls-files`로 확인하세요.
- 비밀번호, 토큰, DB 주소를 캡처하거나 채팅에 붙여 넣지 마세요. 진단할 때는 값을 `***`로 가린 출력만 씁니다.
- 백업 파일(JSON, SQL)에는 계정 해시가 들어 있습니다. 개인 매체에만 보관하세요.
- 과거 커밋에 `.env`나 `backup/` 파일이 남아 있을 수 있습니다. 저장소를 공개하기 전에 기록을 정리하세요.

</details>

<details>
<summary><b>14. 시연 전 확인 목록</b></summary>

- [ ] Render 배포가 성공했고 시작 에러가 없음
- [ ] `/api/health` 응답 확인
- [ ] 회원가입 → 로그인 → 구역 선택 → 대시보드 진입
- [ ] 새 PC 연결 후 측정값 표시
- [ ] 일반 사용자 계정에서는 본인 PC만 보임
- [ ] 관리자 계정에서는 전체 장비가 보임
- [ ] 차단 흐름: 탐지 → 승인 → 종료 확인
- [ ] 노트북 절전 해제, `AUTO_ENROLL_VLAN` 비어 있음
- [ ] 브라우저에서 `Ctrl+F5` 후 다시 로그인

</details>
