# MCP Dynamic Analyzer

**MCP 서버 보안 취약점 진단 파이프라인의 동적 분석 모듈.**

서버가 뭘 말하는가(description)가 아니라 **서버가 뭘 하는가(behavior)**를 검사함.
격리된 Docker 샌드박스에서 대상 서버를 실제로 실행하고, 프로토콜·OS·LLM 세 계층을 동시에 관찰하여 6가지 보안 위험을 탐지함.

```
[정적 분석 모듈] → [동적 분석 모듈 ← 이 프로젝트] → [취약성 산정 / 리포팅 모듈]
```

---

## 목차

1. [현재 실행 가능 여부](#현재-실행-가능-여부)
2. [설치](#설치)
3. [프로세스 체인 상세](#프로세스-체인-상세)
4. [사용 방법](#사용-방법)
5. [Docker 샌드박스 설정](#docker-샌드박스-설정)
6. [설정 파일 레퍼런스](#설정-파일-레퍼런스)
7. [출력 형식](#출력-형식)
8. [구현 상태](#구현-상태)

---

## 현재 실행 가능 여부

### 즉시 동작하는 기능 (--no-docker 모드)

| 기능 | 상태 | 설명 |
|---|---|---|
| MCP 핸드셰이크 + 도구 목록 수집 | ✅ 동작 | `initialize` → `tools/list` → `resources/list` → `prompts/list` |
| R3: 프롬프트 인젝션 탐지 | ✅ 동작 | tool description 패턴 분석 + tool return injection |
| R5: 입력 처리 취약성 퍼징 | ✅ 동작 | 경로순회·CMDi·SQLi·타입혼동 페이로드 자동 전송 |
| Chain Attack 분석 | ✅ 동작 | tool 호출 체인 데이터 흐름 추적 |
| R4: 행동 불일치 | ✅ 동작 | tools/list 변화 감지, env-variation diff |
| R6: 안정성 | ✅ 동작 | 크래시·타임아웃·에러율 탐지 |
| EventStore (JSONL) | ✅ 동작 | 모든 이벤트 append-only 기록, 재분석 가능 |
| 상관관계 엔진 | ✅ 동작 | 크로스-스캐너 인과관계 링크 |
| 점수화 + JSON export | ✅ 동작 | per-risk 정규화 점수, verdict (REJECT/CONDITIONAL/APPROVE) |
| Markdown 리포트 | ✅ 동작 | `report.md` 자동 생성 |
| 재분석 CLI | ✅ 동작 | `analyze --session` 으로 기존 데이터에 새 스캐너 적용 |

### Docker 모드 필요 기능

| 기능 | 상태 | 선행 조건 |
|---|---|---|
| Docker 샌드박스 격리 | ✅ 동작 | `mcp-sandbox` 이미지 빌드 필요 |
| R1: 민감 파일 접근 탐지 | ⚠️ Docker + strace 필요 | syscall 이벤트는 Docker+strace 없이 수집 안 됨 |
| R2: 비인가 프로세스 실행 탐지 | ⚠️ Docker + strace 필요 | execve 이벤트 필요 |
| 허니팟 canary 유출 탐지 | ⚠️ Docker 필요 | /home/user 허니팟 마운트 필요 |
| 네트워크 모니터링 | ⚠️ Docker 필요 | 컨테이너 내부 소켓 폴링 필요 |

> **결론**: `--no-docker` 모드로 R3·R5·R4·R6·Chain Attack을 즉시 실행할 수 있음.
> R1·R2의 OS 레벨 탐지는 Docker + `mcp-sandbox` 이미지 빌드 후 사용 가능.

---

## 설치

```bash
# 저장소 클론
git clone https://github.com/your-org/mcp-dynamic-analyzer
cd mcp-dynamic-analyzer

# Python 가상환경 생성 및 패키지 설치 (uv 사용)
uv venv
uv pip install -e ".[dev]"

# 또는 pip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 설치 확인
mcp-dynamic-analyzer --help
```

### Docker 이미지 빌드 (선택, R1/R2 필요 시)

```bash
docker build -t mcp-sandbox -f docker/Dockerfile.sandbox .
```

---

## 프로세스 체인 상세

### 전체 실행 흐름

```
mcp-dynamic-analyzer scan --server-path "/absolute/path/to/my_server.py"
        │
        ▼
[1] cli.py: 설정 로드 + build_default_scanners()
        │
        ▼
[2] orchestrator.run_analysis()
        │
        ├── ━━━ 수집 단계 (Collection) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        │   │
        │   ├── [3] Sandbox.__aenter__()
        │   │       ├── Docker 모드: docker run -i --rm --memory 512m
        │   │       │                --read-only --network none
        │   │       │                --tmpfs /tmp:size=100m
        │   │       │                mcp-sandbox <command> <args>
        │   │       └── Local 모드:  subprocess(command, args, stdin=PIPE, stdout=PIPE)
        │   │
        │   ├── [4] StdioInterceptor.start()
        │   │       └── asyncio task: _read_loop() 백그라운드 시작
        │   │           모든 s2c 메시지를 EventWriter에 기록
        │   │
        │   ├── [5] McpClient 생성 → Sequencer 생성
        │   │
        │   ├── [6] Sequencer.run_all() — 시퀀스 순서대로 실행
        │   │   │
        │   │   ├── InitSequence.execute()
        │   │   │   ├── client.initialize()  → {jsonrpc:2.0, method:"initialize", ...}
        │   │   │   │   서버 응답: serverInfo, capabilities
        │   │   │   ├── client.list_tools()  → tools/list
        │   │   │   │   ToolInfo 목록 수집 (name, description, inputSchema)
        │   │   │   ├── client.list_resources()  (선택)
        │   │   │   └── client.list_prompts()    (선택)
        │   │   │
        │   │   └── FuzzingSequence.execute()  (R5 활성화 시)
        │   │       ├── 각 tool의 string 파라미터에 페이로드 주입
        │   │       │   ├── path_traversal: ../../../etc/passwd, %2F 인코딩 등 30+종
        │   │       │   ├── command_injection: ;id, |whoami, $(cmd) 등 20+종
        │   │       │   ├── sql_injection: OR '1'='1', DROP TABLE 등 15+종
        │   │       │   └── type_confusion: null, [], {}, 경계값 등 30+종
        │   │       └── 각 tool_call 요청/응답을 EventWriter에 기록
        │   │
        │   ├── [7] Sandbox.__aexit__() → 컨테이너 kill + 정리
        │   │
        │   └── [8] R4 env-variation 루프 (env_variations > 0)
        │           └── USER/TZ/LANG 변경한 추가 컨테이너에서 InitSequence 재실행
        │               variation_tag="env_0", "env_1", ... 으로 이벤트 구분
        │
        └── ━━━ 분석 단계 (Analysis) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            │
            ├── [9] EventReader로 events.jsonl 읽기
            │
            ├── [10] 각 Scanner.analyze(ctx) 병렬 실행
            │   │
            │   ├── R1DataAccessScanner
            │   │   ├── syscall:file_open 이벤트 → 민감 경로 접근 탐지
            │   │   ├── honeypot:honeypot_access 이벤트 → 허니팟 접근 탐지
            │   │   ├── protocol 응답에서 canary 문자열 검색
            │   │   └── network:outbound_connection → SSRF/내부 IP 접근 탐지
            │   │
            │   ├── R2CodeExecScanner
            │   │   ├── syscall:process_exec 이벤트 → shell/interpreter 실행 탐지
            │   │   └── test:test_input과 시간 매칭 → CMDi 성공 상관관계
            │   │
            │   ├── R3LlmManipulationScanner
            │   │   ├── ToolInfo.description 패턴 매칭 (injection_patterns.py)
            │   │   │   ├── hidden_instruction: "ignore previous", "SYSTEM:"
            │   │   │   ├── role_assumption: "act as", "you are now"
            │   │   │   ├── data_exfiltration: "send to", "POST to http"
            │   │   │   ├── stealth: "do not mention", "hidden"
            │   │   │   └── encoded_content: base64, hex 인코딩 의심 패턴
            │   │   └── mcp_response 이벤트 응답에서 return injection 탐지
            │   │
            │   ├── R4BehaviorDriftScanner
            │   │   ├── base vs env_N 태그 비교 → tools/list 변화 탐지 (Rug Pull)
            │   │   └── 선언 capability vs 실제 호출 불일치 탐지
            │   │
            │   ├── R5InputValidationScanner
            │   │   ├── test:test_input 이벤트 페이로드별 성공 지표 검색
            │   │   │   ├── path_traversal: "root:x:", "HOME=", "/etc/passwd" 내용
            │   │   │   ├── cmd_injection: "uid=", "gid=", CMDINJECTION_CANARY
            │   │   │   └── sql_injection: SQL 에러 메시지 (syntax error, ORA- 등)
            │   │   └── 에러 응답에서 스택 트레이스 유출 탐지
            │   │
            │   ├── R6StabilityScanner
            │   │   ├── test:server_crash 이벤트 탐지
            │   │   ├── test:sequence_timeout 이벤트 탐지
            │   │   └── 에러 응답 비율 계산
            │   │
            │   └── ChainAttackScanner
            │       ├── tool 호출 체인 재구성 (요청-응답 페어링)
            │       ├── 이전 응답 → 다음 요청 argument 데이터 흐름 추적
            │       └── 민감 키워드 포함 체인 플래그
            │
            ├── [11] CorrelationEngine.correlate()
            │   ├── R5 페이로드 전송 시점 ↔ R2 execve 탐지 → 인과 링크
            │   ├── R5 페이로드 ↔ R1 파일 접근 → 인과 링크
            │   ├── R3 인젝션 ↔ R1 데이터 유출 → 인과 링크
            │   └── 중복 finding 병합 (동일 tool + 동일 위험 유형)
            │
            ├── [12] Scorer.score()
            │   ├── per-risk score = min(Σ(severity_weight × confidence) / 2.0, 1.0)
            │   ├── overall = max(per-risk scores)
            │   └── verdict: ≥0.75 → REJECT, ≥0.4 → CONDITIONAL, else APPROVE
            │
            └── [13] 출력
                ├── results/{session_id}/events.jsonl  ← 모든 원시 이벤트
                ├── results/{session_id}/findings.json ← AnalysisOutput JSON
                ├── results/{session_id}/report.md     ← 사람이 읽는 Markdown 리포트
                └── stderr: rich 테이블 요약 (risk 점수, verdict, top findings)
```

### 이벤트 흐름 (StdioInterceptor)

```
TestClient (McpClient)              StdioInterceptor           Target Server
       │                                   │                        │
       │── send_request("initialize") ────▶│                        │
       │                                   │── stdin.write() ──────▶│
       │                                   │   (EventWriter 기록)    │
       │                                   │◀─ stdout.readline() ───│
       │                                   │   (EventWriter 기록)    │
       │◀─ Future.set_result(response) ────│                        │
       │                                   │                        │
       │── send_request("tools/call",      │                        │
       │     {"name": "read_file",         │                        │
       │      "arguments": {"path":        │                        │
       │        "../../../etc/passwd"}}) ──▶│── stdin.write() ──────▶│
       │                                   │   ← test:test_input    │
       │                                   │◀─ stdout.readline() ───│
       │                                   │   ← protocol:mcp_resp  │
       │◀─ Future.set_result(response) ────│                        │
```

---

## 사용 방법

### 기본 스캔 (no-Docker, 즉시 실행 가능)

```bash
# 절대 경로 기반 (권장)
mcp-dynamic-analyzer scan --no-docker \
    --server-path "/Users/woojin/Desktop/Univ./Grade4/Integrated Project/mcp-dynamic-analyzer/tests/fixtures/benign_server.py"

# JS 서버 절대 경로 (runtime 자동 감지: node)
mcp-dynamic-analyzer scan --no-docker \
    --server-path "/absolute/path/to/server.mjs"

# 실행 파일(바이너리) 절대 경로
mcp-dynamic-analyzer scan --no-docker \
    --server-path "/absolute/path/to/mcp-server-bin" \
    --server-runtime exec

# 기존 커맨드 모드도 계속 사용 가능
mcp-dynamic-analyzer scan --no-docker \
    --server "npx @modelcontextprotocol/server-filesystem /tmp"

# 빠른 스캔 (R1+R3+R5만, ~60초)
mcp-dynamic-analyzer scan --no-docker --quick \
    --server "npx @modelcontextprotocol/server-filesystem /tmp"

# JSON 출력 (CI/CD 파이프라인 연동)
mcp-dynamic-analyzer scan --no-docker --format json \
    --server-path "/absolute/path/to/my_mcp_server.py" > result.json
```

### Docker 샌드박스 스캔

Docker 모드가 **기본값**입니다. `--no-docker`를 붙이지 않으면 자동으로 컨테이너 안에서 실행됩니다.
컨테이너에서 실행할 때는 호스트 CWD가 `/workspace`로 마운트되므로, 상대 경로가 그대로 동작합니다.

```bash
# 1. mcp-sandbox 이미지 먼저 빌드 (최초 1회)
docker build -t mcp-sandbox -f docker/Dockerfile.sandbox .

# 2. Python 서버 Docker 스캔 (상대 경로 OK — CWD가 /workspace로 마운트됨)
mcp-dynamic-analyzer scan \
    --server "python tests/fixtures/malicious_server.py"

# 3. Node.js 서버 Docker 스캔
mcp-dynamic-analyzer scan \
    --server "npx @modelcontextprotocol/server-filesystem /tmp"

# 4. 절대 경로로 서버 지정 (--server-path 사용)
mcp-dynamic-analyzer scan \
    --server-path /absolute/path/to/my_server.py

# 5. Docker + JSON 출력 (CI/CD)
mcp-dynamic-analyzer scan --format json \
    --server "python tests/fixtures/malicious_server.py" > result.json
```

> **참고**: `--server "python ..."` 대신 `--server-path`를 쓰면 런타임을 자동 감지합니다 (`.py` → `python3`, `.js` → `node`).
> Docker 모드에서는 컨테이너 안에 `strace`가 설치돼 있으면 syscall 이벤트(R1/R2)도 수집됩니다.

### 설정 파일로 스캔

```bash
# 설정 파일 수정
cat > my-scan.yaml << 'EOF'
server:
  command: "npx"
  args: ["@modelcontextprotocol/server-filesystem", "/tmp"]
  env: {}
  transport: "stdio"

sandbox:
  memory_limit: "512m"
  cpu_limit: 0.5
  timeout: 120
  network:
    mode: "none"

scanners:
  r3_llm_manipulation:
    enabled: true
  r5_input_validation:
    enabled: true
    fuzz_rounds: 5

output:
  output_dir: "./results"
EOF

mcp-dynamic-analyzer scan --no-docker --config my-scan.yaml
```

### 이전 세션 재분석

```bash
# 기존 events.jsonl을 새 스캐너 설정으로 재분석
mcp-dynamic-analyzer analyze \
    --session ./results/ses-abc123/ \
    --config configs/default.yaml
```

### 출력 디렉터리 확인

```bash
ls results/ses-<uuid>/
# events.jsonl   ← 모든 원시 이벤트 (JSONL)
# findings.json  ← 구조화된 분석 결과
# report.md      ← Markdown 리포트
```

---

## Docker 샌드박스 설정

### 컨테이너 보안 설정 (sandbox.py 기반)

```
docker run
  -i --rm
  --memory 512m          # 메모리 제한
  --cpus 0.5             # CPU 제한 (50%)
  --read-only            # 루트 파일시스템 읽기 전용
  --tmpfs /tmp:size=100m # /tmp만 쓰기 가능
  --security-opt no-new-privileges
  --network none         # 네트워크 완전 차단 (기본)
  mcp-sandbox
  <server-command> <args>
```

### 네트워크 모드

| 모드 | 설정 | 용도 |
|---|---|---|
| `none` | `network.mode: "none"` | 기본값. 외부 통신 완전 차단. |
| `allowlist` | `network.mode: "allowlist"` | 허용 도메인만 통신 가능. 내부 IP 자동 차단. |

### Dockerfile.sandbox 주요 내용

```dockerfile
FROM ubuntu:24.04
RUN apt-get install -y nodejs npm python3 strace inotify-tools
RUN useradd -m -s /bin/bash user
WORKDIR /workspace
USER user
```

---

## 설정 파일 레퍼런스

### `configs/default.yaml`

```yaml
server:
  command: ""                    # 실행할 MCP 서버 명령
  args: []                       # 명령 인자
  env: {}                        # 추가 환경 변수
  transport: "stdio"             # "stdio" | "http"
  http_port: null                # HTTP 모드 시 포트

sandbox:
  memory_limit: "512m"
  cpu_limit: 0.5
  timeout: 300                   # 전체 분석 타임아웃 (초)
  network:
    mode: "none"                 # "none" | "allowlist"
    allowlist: []                # 허용 도메인 목록
    block_internal: true         # 내부 IP 자동 차단
    log_all_traffic: true

scanners:
  r1_data_access:
    enabled: true                # syscall/honeypot 이벤트 분석
  r2_code_exec:
    enabled: true                # execve 이벤트 분석
  r3_llm_manipulation:
    enabled: true
    llm_api: null                # null=패턴 매칭만, "anthropic"=LLM 영향도 테스트
  r4_behavior_drift:
    enabled: true
    repeat_count: 3
    env_variations: 2            # 추가 컨테이너로 환경 차분 분석 횟수
  r5_input_validation:
    enabled: true
    fuzz_rounds: 10              # 도구당 퍼징 라운드
  r6_stability:
    enabled: true
    stress_duration: 30

output:
  output_dir: "./results"
```

### `configs/quick.yaml`

R1·R2·R4·R6 비활성화, R5 fuzz_rounds=3, timeout=60초. 빠른 초기 검증용.

---

## 출력 형식

### `findings.json`

```json
{
  "session_id": "ses-550e8400-...",
  "server": {"name": "npx", "args": ["@mcp/server", "/tmp"]},
  "findings": [
    {
      "finding_id": "fnd-...",
      "risk_type": "R3",
      "severity": "HIGH",
      "confidence": 0.85,
      "title": "Suspicious pattern 'hidden_instruction' in tool description",
      "description": "Tool 'execute_code' description contains...",
      "related_events": ["evt-..."],
      "tool_name": "execute_code",
      "reproduction": "Inspect description of tool 'execute_code'",
      "detected_at": "2026-04-05T10:05:00.000000+00:00"
    }
  ],
  "event_log_path": "./results/ses-.../events.jsonl",
  "dynamic_risk_scores": {
    "R1": 0.0, "R2": 0.0, "R3": 0.75,
    "R4": 0.0, "R5": 0.5, "R6": 0.0
  },
  "metadata": {
    "duration_sec": 0,
    "tools_tested": 5,
    "total_events": 342,
    "overall_score": 0.75,
    "verdict": "REJECT"
  }
}
```

### `report.md` 구조

```
# MCP Dynamic Analyzer — Security Report
## Verdict          ← REJECT / CONDITIONAL / APPROVE + 점수
## Risk Score Summary  ← R1~R6 점수 테이블
## Severity Breakdown  ← CRITICAL/HIGH/MEDIUM/LOW/INFO 카운트
## Scan Metadata
## Findings         ← 위험 유형별, 심각도 순 상세 기술
   ### R3: LLM Behavior Manipulation
   #### 🔴 Suspicious pattern ...
        finding_id / severity / confidence / tool / detected_at
        description
        related events
        reproduction 방법 (코드 블록)
```

### stderr 터미널 요약

```
  Verdict: REJECT  (overall score: 0.75)

┌──────────────────────────────────────────────────┐
│ MCP Dynamic Analysis — ses-abc123                │
├──────────────────────┬────────┬──────────┤
│ Risk Type            │  Score │ Findings │
├──────────────────────┼────────┼──────────┤
│ R1: Data Access      │   0.00 │        0 │
│ R2: Code Execution   │   0.00 │        0 │
│ R3: LLM Manipulation │   0.75 │        3 │
│ R4: Behavior Drift   │   0.00 │        0 │
│ R5: Input Validation │   0.50 │        2 │
│ R6: Stability        │   0.00 │        0 │
└──────────────────────┴────────┴──────────┘
  Severity breakdown: HIGH: 3, MEDIUM: 2
  Tools tested: 5  |  Events: 342  |  Findings: 5
```

---

## 구현 상태

### 수집 단계

| 컴포넌트 | 파일 | 상태 |
|---|---|---|
| Docker Sandbox | `infrastructure/sandbox.py` | ✅ |
| stdio 인터셉터 | `protocol/interceptor.py` | ✅ |
| HTTP/SSE 인터셉터 | `protocol/http_interceptor.py` | ✅ (미통합) |
| MCP 테스트 클라이언트 | `protocol/client.py` | ✅ |
| 시퀀서 + 에러 격리 | `protocol/sequencer.py` | ✅ |
| syscall 추적 (strace) | `infrastructure/sysmon.py` | ✅ (오케스트레이터 미통합) |
| 허니팟 파일시스템 | `infrastructure/honeypot.py` | ✅ (오케스트레이터 미통합) |
| 네트워크 모니터 | `infrastructure/netmon.py` | ✅ (오케스트레이터 미통합) |
| EventStore (JSONL) | `correlation/event_store.py` | ✅ |

### 분석 단계

| 컴포넌트 | 파일 | 상태 |
|---|---|---|
| R1: 데이터 접근 | `scanners/r1_data_access.py` | ✅ (syscall 이벤트 없으면 탐지 제한) |
| R2: 코드 실행 | `scanners/r2_code_exec.py` | ✅ (syscall 이벤트 없으면 탐지 제한) |
| R3: LLM 조작 | `scanners/r3_llm_manipulation.py` | ✅ 즉시 동작 |
| R4: 행동 불일치 | `scanners/r4_behavior_drift.py` | ✅ 즉시 동작 |
| R5: 입력 취약성 | `scanners/r5_input_validation.py` | ✅ 즉시 동작 |
| R6: 안정성 | `scanners/r6_stability.py` | ✅ 즉시 동작 |
| Chain Attack | `scanners/chain_attack.py` | ✅ 즉시 동작 |
| 상관관계 엔진 | `correlation/engine.py` | ✅ |
| 점수화 | `output/scorer.py` | ✅ |
| JSON export | `output/exporter.py` | ✅ |
| Markdown 리포트 | `output/reporter.py` | ✅ |

### 미완성 / 향후 과제

| 항목 | 설명 |
|---|---|
| OS 모니터 오케스트레이터 통합 | sysmon/honeypot/netmon이 `_collect()`에서 시작되지 않음 → R1/R2 syscall 이벤트 없음 |
| LLM 영향도 테스트 (R3) | `llm_api: "anthropic"` 설정 시 실제 Claude API 호출 미구현 |
| HTTP/SSE 서버 지원 | `http_interceptor.py` 구현됐으나 오케스트레이터에 미연결 |
| 스캐너 테스트 | `tests/test_scanners/test_all_scanners.py`에 R1~R6·chain 통합; 파일별 분리는 선택 |
| `duration_sec` 측정 | 현재 0으로 고정 |

---

## 요구사항

- Python 3.11+
- Docker (R1/R2 OS 레벨 탐지 + 샌드박스 격리 시 필요)
- strace (Docker 컨테이너 내 syscall 추적 시 필요, Dockerfile.sandbox에 포함)

## 라이선스

MIT
