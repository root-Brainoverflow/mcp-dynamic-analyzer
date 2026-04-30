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
6. [백엔드 사이드카 (DB 의존 서버)](#백엔드-사이드카-db-의존-서버)
7. [Syscall 추적](#syscall-추적)
8. [탐지 정밀도와 FP 차단](#탐지-정밀도와-fp-차단)
9. [퍼징 페이로드 카탈로그](#퍼징-페이로드-카탈로그)
10. [설정 파일 레퍼런스](#설정-파일-레퍼런스)
11. [출력 형식](#출력-형식)
12. [구현 상태](#구현-상태)
13. [요구사항](#요구사항)

---

## 현재 실행 가능 여부

### 즉시 동작하는 기능 (--no-docker 모드)

| 기능 | 상태 | 설명 |
|---|---|---|
| MCP 핸드셰이크 + 도구 목록 수집 | ✅ 동작 | `initialize` → `tools/list` → `resources/list` → `prompts/list` |
| R3: 서버 유도형 LLM 조작 탐지 | ✅ 동작 | tool metadata/response 분석 + 관찰된 resource body poisoning 탐지 |
| R5: 입력 처리 취약성 퍼징 | ✅ 동작 | 경로순회·CMDi·SQLi·타입혼동 페이로드 자동 전송 |
| Chain Attack 분석 | ✅ 동작 | 서버가 제공한 tool metadata의 위험한 유도/오표시 탐지 |
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
| Docker 샌드박스 격리 | ✅ 동작 | `docker/profiles/build.sh` 로 프로파일 이미지 빌드 필요 |
| R1: 민감 파일 접근 탐지 | ✅ Docker+strace로 풀 커버리지 / ⚠️ 로컬은 lsof·psutil fallback (file_read/write 누락) | Docker 모드는 `docker exec strace -p 1`로 컨테이너 내부 attach |
| R2: 비인가 프로세스 실행 탐지 | ✅ Docker+strace는 execve, 로컬 fallback은 child-process 폴링 | 로컬에서는 짧은 수명 프로세스 누락 가능 |
| 허니팟 canary 유출 탐지 | ⚠️ Docker 필요 | /home/user 허니팟 마운트 필요 |
| 네트워크 모니터링 | ⚠️ Docker 필요 | 컨테이너 내부 소켓 폴링 필요 |
| **백엔드 사이드카** (postgres / mysql / mongo / redis MCP) | ✅ 동작 | private `--internal` 네트워크 + 자격증명 자동 redirect. 호스트 DB는 절대 접근 불가 |
| **DoS hang circuit breaker** | ✅ 동작 | (tool, category)당 첫 timeout으로 카테고리 전체 단축 — `nan`/`inf`/`hash_collision` 같은 hang이 글로벌 예산을 잠식하지 못함 |
| **payload reflection FP 차단** | ✅ 동작 | Pydantic / jsonschema / postgres LINE / MySQL `near` echo 패턴을 strip 후 indicator 매칭 |

> **결론**: `--no-docker` 모드로 R3·R5·R4·R6·Chain Attack을 즉시 실행할 수 있음.
> R1·R2의 OS 레벨 탐지는 Docker + `mcp-sandbox` 이미지 빌드 후 사용 가능.
> postgres-mcp 같은 백엔드 의존 서버는 Docker 모드에서 사이드카가 자동으로 뜨고 user의 prod 자격증명은 사이드카로 강제 우회됨.

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

### Docker 프로파일 이미지 빌드 (선택, R1/R2 필요 시)

샌드박스는 서버 런타임에 맞는 이미지를 자동으로 선택합니다.
추가로 스캔 대상 MCP 서버의 소스 경로(`args`에 절대 경로가 있는 경우) 또는
원격 패키지 registry(npx/uvx 등 패키지 런처인 경우)를 사전 분석하여
필요한 선행 구성요소를 추론하고, 선택된 베이스 이미지 위에 bootstrap 레이어를
동적으로 빌드한 뒤 그 이미지로 스캔을 진행합니다.
최초 1회 모든 프로파일을 빌드합니다.

```bash
./docker/profiles/build.sh
# → mcp-sandbox-node20, mcp-sandbox-node22,
#   mcp-sandbox-python311, mcp-sandbox-python312,
#   mcp-sandbox-polyglot (fallback)
```

### 선행 구성요소 사전 분석 및 Bootstrap 로직

MCP 서버는 실행 커맨드만 보고는 필요한 선행 구성요소를 파악하기 어렵습니다.
`node:22` 이미지만으로 뜨는 서버가 있는 반면, Playwright 기반 서버는 브라우저 바이너리까지,
음악 처리 서버는 `ffmpeg`까지 필요할 수 있습니다.
그래서 Sandbox는 서버를 실제로 실행하기 **전에** 선행 구성요소를 추론하고,
필요하다면 베이스 이미지 위에 설치 레이어를 추가한 파생 이미지를 빌드해서 스캔을 시작합니다.
이 전체 과정을 **bootstrap** 이라고 합니다.

Bootstrap은 크게 세 단계로 이루어집니다.

```
[1] Preflight  →  [2] Plan & Build  →  [3] Retry (실패 시)
  의존성 파악       Dockerfile 생성       stderr 분석 후 재빌드
                   docker build
                   파생 이미지 캐시
```

---

#### 1단계: Preflight — 의존성 파악

`SourcePreflightInspector`가 서버 실행 전에 의존성과 source signal을 수집합니다.
로컬 manifest를 우선하고, 없으면 원격 registry를 조회합니다.

**소스 manifest 분석 (서버 args에 절대 경로가 있는 경우)**

`server.args`에 절대 경로가 있으면 (`python /path/to/server.py` 등) 해당 경로에서
위로 최대 5단계까지 올라가며 아래 파일을 탐색합니다.
호스트 환경 전체를 스캔하는 것이 아니라 스캔 대상 서버의 소스 트리를 따라갑니다.

- `package.json`
- `pyproject.toml`
- `requirements.txt`

manifest를 찾으면 의존성을 파싱하고, 프로젝트 루트의 소스 파일(`.py`, `.js`, `.ts`)도 재귀 스캔해서 capability signal을 추출합니다.

Node 의존성 필드:
- `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`

Python 의존성 필드:
- `project.dependencies`, `project.optional-dependencies`, `dependency-groups`
- `tool.poetry.dependencies`, `requirements.txt`

**원격 패키지 조회 (`npx`/`uvx`/`pipx` 등 패키지 런처)**

로컬 manifest가 없고 네트워크 모드가 `allowlist`이면, **호스트에서** 직접 registry metadata만 조회합니다.
소스 코드를 다운로드하거나 스캔하지 않으며, 선언된 의존성 목록만 가져옵니다.

- Node (`npx`, `pnpx`, `bunx`):
  - 커맨드에서 패키지 spec 추출 (예: `npx -y @playwright/mcp@latest` → `@playwright/mcp@latest`)
  - `npm view <spec> --json` 을 호스트에서 실행 (최대 30초 타임아웃)
  - 반환된 JSON에서 `dependencies`, `peerDependencies` 파싱
- Python (`uvx`, `pipx`):
  - 커맨드에서 패키지명 추출 (예: `uvx some-python-mcp` → `some-python-mcp`)
  - PyPI JSON API `https://pypi.org/pypi/{pkg}/json` 를 호스트에서 조회
  - `info.requires_dist` 필드 파싱

> **Source signal 제한**: `channel: "chrome"` 같은 source signal은 소스 코드를 직접 읽는
> 로컬 서버에서만 검출됩니다. 원격 패키지 런처 기반 서버는 의존성 목록만 확인하므로
> signal 없이는 기본값인 `chromium` 레시피가 적용됩니다.

**Source signal 추출**

의존성 목록과 별개로, 소스 코드나 실행 커맨드에서 더 구체적인 prerequisite를 암시하는 패턴을 찾습니다.

| Signal | 의미 |
|--------|------|
| `channel: “chrome”` | Google Chrome 바이너리 필요 |
| `google-chrome`, `/opt/google/chrome/chrome` | Google Chrome 바이너리 필요 |
| `playwright install` (stderr) | Playwright 브라우저 미설치 상태 |

---

#### 2단계: Plan & Build — Dockerfile 생성과 이미지 빌드

Preflight 결과가 나오면 `plan_bootstrap()`이 YAML 레시피 파일과 매칭해서 구체적인 설치 명령 목록(`BootstrapPlan`)을 만들고, 이를 Dockerfile로 렌더링해서 `docker build`로 파생 이미지를 빌드합니다.

**레시피 매칭 (`infrastructure/recipes/builtin.yaml`)**

각 레시피는 AND 조건(`runtime_prefix`, `source_signals_any/none`)과 OR 조건(`any_of` 블록)으로 구성됩니다.
Preflight에서 수집한 의존성·signal·커맨드를 `MatchContext`로 변환해서 레시피와 대조합니다.

현재 내장 레시피 목록:

**런타임 prerequisite (이미지 빌드 필요)**

| 레시피 ID | 조건 | 설치 내용 |
|-----------|------|-----------|
| `playwright-node-chromium` | Node + `playwright` 의존성 | `npx playwright install --with-deps chromium` |
| `playwright-node-chrome` | Node + `playwright` + chrome signal | `npx playwright install --with-deps chrome` |
| `playwright-python-chromium` | Python + `playwright` 의존성 | `pip install playwright && playwright install chromium` |
| `playwright-python-chrome` | Python + `playwright` + chrome signal | `pip install playwright && playwright install chrome` |
| `puppeteer-node` | Node + `puppeteer` 의존성 | `npx puppeteer browsers install chrome` |
| `postgres-mcp-python-install` | Python 이미지 + postgres-mcp 토큰 | `pip install postgres-mcp` (런타임 네트워크가 `--internal`이라 빌드 타임에 미리 설치) |
| `postgres-mcp-node-install` | Node 이미지 + `@modelcontextprotocol/server-postgres` 토큰 | `npm install -g @modelcontextprotocol/server-postgres` |

**백엔드 사이드카 (런타임 무관)** — [§백엔드 사이드카](#백엔드-사이드카-db-의존-서버) 참조

| 레시피 ID | 트리거 | 사이드카 |
|---|---|---|
| `postgres-mcp-sidecar` | postgres-mcp / server-postgres 토큰 | `postgres:16-alpine` alias=db |
| `mysql-mcp-sidecar` | mysql-mcp / server-mysql 토큰 | `mysql:8.4` alias=db |
| `mongodb-mcp-sidecar` | mongodb-mcp / server-mongodb 토큰 | `mongo:7` alias=db |
| `redis-mcp-sidecar` | redis-mcp / server-redis 토큰 | `redis:7-alpine` alias=cache |

레시피에 없는 일반 시스템 라이브러리는 3단계 동적 heuristic이 처리합니다.

**Recipe YAML 필드 전체**

| 필드 | 타입 | 효과 |
|---|---|---|
| `id` | str | 레시피 고유 ID (action 캐싱·dedup 키) |
| `description` | str | 사람이 읽는 설명 |
| `match.runtime_prefix` | str | 베이스 이미지 이름 prefix가 일치해야 함 (AND) |
| `match.source_signals_any/none` | list | source 스캔에서 추출된 signal 일치/배제 (AND) |
| `match.any_of` | list[block] | 한 블록이라도 매칭되면 통과 (OR) |
| `match.{node\|python}_deps_any` | list | 의존성 목록에 포함 |
| `match.identity_tokens_any` | list | command/args 안에 component-boundary로 매칭 |
| `match.stderr_tokens_any` | list | stderr 안에 substring 매칭 (boundary 검사 없음) |
| `match.package_name_any` | list | preflight package_name에 component-boundary로 매칭 |
| `dockerfile_lines` | list[str] | 베이스 이미지 위에 추가할 Dockerfile 라인 (이미지 빌드 트리거) |
| `env` | dict | 컨테이너 env. `services`가 있는 recipe면 user env를 override |
| `services` | list[ServiceSpec] | 사이드카 컨테이너 정의. `alias`, `image`, `env`, `health_cmd`, `port`, `startup_timeout_sec` |
| `arg_rewrites` | list[{pattern, replacement}] | regex로 args 안의 특정 패턴 (보통 connection URI)을 사이드카 주소로 치환 |

**버전 고정**

Preflight에서 의존성 버전이 확인된 경우, 레시피의 기본 설치 명령에 버전을 고정합니다.

- `^1.49.0` → `1.49.0` (semver 정규화)
- `1.60.0-alpha-1774999321000` (pre-release) → 그대로 보존
- Node: `npx -y playwright@1.49.0 install --with-deps chromium`
- Python: `python3 -m pip install --no-cache-dir playwright==1.49.0`

**파생 이미지 빌드와 캐시**

Bootstrap plan이 결정되면 베이스 이미지를 수정하지 않고 임시 Dockerfile을 생성해서 파생 이미지를 빌드합니다.

```
베이스: mcp-sandbox-node22
파생:   mcp-sandbox-node22-bootstrap-<plan-hash>
```

이미지 태그는 plan 내용의 SHA-256 해시 앞 12자리로 만들기 때문에,
동일한 bootstrap action 조합이면 다음 실행에서 `docker build` 없이 캐시된 이미지를 재사용합니다.

빌드 실패 시에는 경고 로그만 남기고 베이스 이미지로 스캔을 계속합니다. 스캔 자체는 중단되지 않습니다.

---

#### 3단계: Retry — stderr 분석 후 재빌드

서버가 기동 직후(0.3초 이내) 종료되면 서버가 남긴 stderr를 분석해서 누락된 구성요소를 파악하고,
새 이미지를 즉석으로 빌드한 뒤 **한 번만** 재시도합니다.

분석은 두 레이어로 동작합니다.

**Layer 1 — 레시피 재매칭 (stderr_tokens_any)**

레시피의 `stderr_tokens_any` 조건을 stderr에 대해 다시 평가합니다.
Preflight 때는 발견되지 않았던 패턴이 실제 실행 stderr에서 나타났을 때 해당 레시피를 추가로 적용합니다.

예:
- `”playwright install”` 또는 `”chromium distribution 'chrome' is not found”` → Playwright 레시피 적용

**Layer 2 — 동적 apt 패키지 추론**

레시피로 커버되지 않는 일반 시스템 라이브러리를 stderr 패턴으로 직접 매핑합니다.

```
“X: command not found”                              → _COMMAND_TO_APT[“X”]
“cannot open shared object file: libY.so.N”         → _LIB_TO_APT[“libY”]
```

내장 매핑 예시:

| stderr 패턴 | apt 패키지 |
|-------------|-----------|
| `ffmpeg: command not found` | `ffmpeg` |
| `git: command not found` | `git` |
| `convert: command not found` | `imagemagick` |
| `libGL.so.1: cannot open` | `libgl1` |
| `libpq.so.5: cannot open` | `libpq5` |
| `libasound.so.2: cannot open` | `libasound2` |

두 레이어에서 수집된 설치 명령을 합쳐서 동적 Dockerfile을 생성하고 `docker build`합니다.
이 동적 이미지도 content-hash 기반으로 캐시됩니다.

재빌드 이후에도 서버가 다시 즉시 종료되면 스캔을 중단하고 오류를 반환합니다.

---

#### Bootstrap 전체 흐름 요약

```
scan 실행
  │
  ├─ RuntimeResolver
  │    └─ command(“npx”/”python”/…) → 베이스 이미지 선택
  │         예) npx → mcp-sandbox-node22
  │
  ├─ SourcePreflightInspector.inspect()
  │    ├─ 로컬 manifest 발견? → package.json / pyproject.toml 파싱 + 소스 스캔
  │    └─ 없으면 → npm view / PyPI JSON API 조회 (호스트에서, 최대 30초)
  │
  ├─ plan_bootstrap()
  │    ├─ _build_match_context(): 의존성 + signal + 커맨드 → MatchContext
  │    ├─ RecipeRegistry.match(ctx): builtin.yaml 레시피 AND/OR 평가
  │    └─ _pin_playwright_version(): 버전 고정 후처리
  │
  ├─ render_bootstrap_dockerfile() → docker build → 파생 이미지 (캐시)
  │
  ├─ docker run ... 파생이미지 <command> <args>
  │
  └─ 0.3초 이내 즉시 종료? → _retry_bootstrap_from_stderr()
       ├─ Layer 1: 레시피 stderr_tokens_any 재매칭
       ├─ Layer 2: _apt_packages_from_stderr() 동적 heuristic
       ├─ docker build → 동적 이미지 (캐시)
       └─ docker run ... 동적이미지 <command> <args>  (1회만)
```

---

## 프로세스 체인 상세

### 전체 실행 흐름

```
mcp-dynamic-analyzer scan --target <name>
        │
        ▼
[1] cli.py: discover_servers() → select_server() → 설정 로드 + build_default_scanners()
        │
        ▼
[2] orchestrator.run_analysis()
        │
        ├── ━━━ 수집 단계 (Collection) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        │   │
        │   ├── [3] Sandbox.__aenter__()
        │   │       ├── Docker 모드: RuntimeResolver → 프로파일 이미지 선택
        │   │       │                PreflightInspector → manifest/package metadata 사전 분석
        │   │       │                BootstrapPlanner → 필요 시 베이스 이미지 위에 선행요건 레이어 빌드
        │   │       │                ★ services 있으면 _start_sidecars():
        │   │       │                  ├ docker network create --internal mcp-net-<id>
        │   │       │                  ├ docker run -d 각 사이드카 (alias=db/cache/...)
        │   │       │                  ├ health_cmd polling (1초 간격, startup_timeout_sec)
        │   │       │                  └ docker inspect로 사이드카 IP 수집 → trusted_internal_ips
        │   │       │                ★ args에 arg_rewrites 적용 (postgres://prod → postgres://scan@db)
        │   │       │                ★ env override: DATABASE_URI 등 12개 변종 → 사이드카 강제
        │   │       │                docker run -i --rm --memory 512m
        │   │       │                [strict]     --read-only --tmpfs /tmp:size=100m  (패키지러너는 512m)
        │   │       │                             --security-opt no-new-privileges --cap-add SYS_PTRACE
        │   │       │                [permissive] --cap-add ALL --security-opt seccomp=unconfined
        │   │       │                [사이드카]   --network mcp-net-<id>  (bridge 대신)
        │   │       │                [패키지러너] -w /tmp -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache
        │   │       │                mcp-sandbox-{node22|python312|...} <command> <args>
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
        │   ├── [7] Sandbox.__aexit__() → 컨테이너 kill + _stop_sidecars()
        │   │       └── 사이드카 kill, docker network rm
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
            │   │      (사이드카 IP는 static_context.trusted_internal_ips로 제외)
            │   │
            │   ├── R2CodeExecScanner
            │   │   ├── syscall:process_exec 이벤트 → shell/interpreter 실행 탐지
            │   │   ├── test:test_input과 시간 매칭 → CMDi 성공 상관관계
            │   │   └── ★ validation rejection 응답은 RCE 검사 short-circuit
            │   │
            │   ├── R3LlmManipulationScanner
            │   │   ├── ToolInfo.description/annotation 패턴 매칭 (injection_patterns.py)
            │   │   │   ├── hidden_instruction: "ignore previous", "SYSTEM:"
            │   │   │   ├── role_assumption: "act as", "you are now"
            │   │   │   ├── data_exfiltration: "send to", "POST to http"
            │   │   │   ├── stealth: "do not mention", "hidden"
            │   │   │   └── encoded_content: base64, hex 인코딩 의심 패턴
            │   │   ├── mcp_response 이벤트 응답에서 return injection 탐지
            │   │   ├── resources/read 응답이 있으면 resource poisoning 탐지
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
            │   │   ├── ★ payloads/_response_filters.is_validation_rejection()로
            │   │   │     Pydantic/jsonschema 거부 응답을 success 검사에서 제외
            │   │   └── 에러 응답에서 스택 트레이스 유출 탐지
            │   │
            │   ├── R6StabilityScanner
            │   │   ├── test:server_crash 이벤트 탐지
            │   │   ├── test:sequence_timeout 이벤트 탐지
            │   │   └── 에러 응답 비율 계산
            │   │
            │   └── ChainAttackScanner
            │       ├── tools/list metadata 기준으로 tool 설명/annotation 검사
            │       ├── readOnlyHint=true 인데 destructive capability를 암시하는 tool 탐지
            │       └── description/annotation이 destructive follow-up tool 호출을 유도하는지 탐지
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

### 1. 로컬 MCP 서버 조회

Claude Desktop, Claude Code, Cursor, VSCode 설정 파일을 자동으로 스캔해
현재 머신에 설정된 MCP 서버 목록을 보여줍니다.

```bash
mcp-dynamic-analyzer discover
```

```
                         Discovered MCP Servers
┏━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ name                ┃ source ┃ command                       ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ filesystem          │ cursor │ npx @mcp/server-filesystem ... │
│ 2 │ github              │ cursor │ npx @github/mcp-server ...     │
│ 3 │ spotify             │ claude-code │ python server.py ...      │
└───┴─────────────────────┴────────┴───────────────────────────────┘

Run: mcp-dynamic-analyzer scan --target <name>
```

스캔 소스 우선순위: `claude-desktop` → `claude-code` → `cursor` → `vscode`

### 2. 서버 선택 후 스캔

```bash
# 기본 (Docker 샌드박스, 권장)
mcp-dynamic-analyzer scan --target filesystem

# 동일 이름이 여러 source에 있을 때 source 지정
mcp-dynamic-analyzer scan --target filesystem --source claude-desktop

# 빠른 스캔 (R3 + R5만, ~60초)
mcp-dynamic-analyzer scan --target filesystem --quick

# Docker 없이 로컬 실행 (즉시 실행 가능, OS 레벨 탐지 제외)
mcp-dynamic-analyzer scan --target filesystem --no-docker

# JSON 출력 (CI/CD 파이프라인)
mcp-dynamic-analyzer scan --target filesystem --format json > result.json
```

> Docker 모드에서는 `RuntimeResolver`가 서버 커맨드(`npx`, `uvx`, `python3.11` 등)를 보고
> 적합한 프로파일 이미지(`mcp-sandbox-node22`, `mcp-sandbox-python312` 등)를 자동 선택합니다.
> `--no-docker` 모드에서는 이런 preflight/bootstrap 단계를 수행하지 않고,
> 현재 호스트 환경에서 서버를 그대로 실행합니다.

### 3. 설정 파일로 스캔 옵션 오버라이드

```bash
cat > my-scan.yaml << 'EOF'
sandbox:
  memory_limit: "1g"
  cpu_limit: 1.0
  timeout: 120
  isolation: "permissive"   # 공개 레지스트리 서버처럼 요구사항 미지의 경우
  network:
    mode: "allowlist"

scanners:
  r3_llm_manipulation:
    enabled: true
  r5_input_validation:
    enabled: true
    fuzz_rounds: 5

output:
  output_dir: "./results"
EOF

mcp-dynamic-analyzer scan --target filesystem --config my-scan.yaml
```

### 4. 이전 세션 재분석

```bash
mcp-dynamic-analyzer analyze \
    --session ./results/ses-abc123/ \
    --config configs/default.yaml
```

### 5. 출력 디렉터리 확인

```bash
ls results/ses-<uuid>/
# events.jsonl   ← 모든 원시 이벤트 (JSONL)
# findings.json  ← 구조화된 분석 결과
# report.md      ← Markdown 리포트
```

---

## Docker 샌드박스 설정

### 런타임 프로파일

`RuntimeResolver`가 서버 커맨드와 프로젝트 매니페스트(`package.json`, `pyproject.toml`)를 보고
자동으로 이미지를 선택합니다. `MCP_SANDBOX_PROFILE` 환경 변수로 오버라이드 가능.

| 이미지 | 기반 | 선택 조건 |
|---|---|---|
| `mcp-sandbox-node22` | `node:22-bookworm-slim` | `npx`, `node`, `npm`, `pnpm` (기본 Node) |
| `mcp-sandbox-node20` | `node:20-bookworm-slim` | `package.json`의 `engines.node` ≤ 20 |
| `mcp-sandbox-python312` | `python:3.12-bookworm` | `uvx`, `python3`, `python3.12` (기본 Python) |
| `mcp-sandbox-python311` | `python:3.11-bookworm` | `python3.11` 또는 `requires-python ~=3.11` |
| `mcp-sandbox-polyglot` | `node:22` + `python3` | 런타임 미식별 fallback |

모든 이미지에 `strace`, `inotify-tools`, `uv`, `mcp` 공통 포함.
필요한 경우 Sandbox가 알려진 server signature/오류 패턴을 보고 base image 위에
선행 component layer를 동적으로 빌드한 뒤 스캔을 시작함.

```bash
# 전체 프로파일 빌드 (최초 1회)
./docker/profiles/build.sh
```

### 격리 모드 (`sandbox.isolation`)

| 모드 | 설명 | 권장 사용처 |
|---|---|---|
| `strict` (기본) | `--read-only`, `no-new-privileges`, `--cap-add SYS_PTRACE` | 신뢰도 높은 서버 |
| `permissive` | `--cap-add ALL`, `seccomp=unconfined`, workspace rw | 공개 레지스트리, 요구사항 미지의 서버 |

> **주의**: permissive 모드도 `--privileged`와 `--network host`는 사용하지 않습니다.
> 샌드박스 내부 자유도와 호스트 격리는 별개입니다.

### 네트워크 모드

| 모드 | 설정 | 용도 |
|---|---|---|
| `allowlist` (기본) | `network.mode: "allowlist"` | Docker bridge — `npx`/`npm` 레지스트리 접근 가능 |
| `none` | `network.mode: "none"` | 외부 통신 완전 차단 |

### docker run 예시 (strict / permissive)

```
# strict
docker run -i --rm --memory 512m --cpus 0.5
  --read-only --tmpfs /tmp:size=100m
  --security-opt no-new-privileges --cap-add SYS_PTRACE
  --network bridge
  mcp-sandbox-node22 npx <args>

# permissive
docker run -i --rm --memory 512m --cpus 0.5
  --cap-add ALL --security-opt seccomp=unconfined --security-opt apparmor=unconfined
  --network bridge
  mcp-sandbox-node22 npx <args>
```

### 패키지 러너의 작업 디렉터리 처리

`uv run`, `uvx`, `npx`, `pnpx`, `bunx`, `pipx` 같은 **패키지 러너 명령**은 호스트의 cwd를 작업 디렉터리로 마운트하지 않습니다. 이유:

- 분석기 자신의 저장소를 cwd로 둔 상태에서 사용자가 `mcp-dynamic-analyzer scan ...`을 실행하면, `uv run`이 분석기 자신의 `.venv/`를 발견하고 갱신하려다 read-only 마운트에서 죽습니다 (실제 사례).
- 패키지 러너는 cwd가 어디든 자기 캐시·venv·lockfile을 만들 수 있으면 됩니다.

따라서 패키지 러너 명령일 때:

| 변경 | 값 |
|---|---|
| `-w` (cwd) | `/tmp` (tmpfs) |
| `--tmpfs /tmp:size=` | 100m → **512m** (uv venv + dep cache 수용) |
| `HOME` | `/tmp` 자동 주입 |
| `XDG_CACHE_HOME` | `/tmp/.cache` 자동 주입 |
| `/workspace` 마운트 | **생략** (단, args에 호스트 절대 경로가 있으면 그 경로만 별도 마운트) |

비-패키지러너 (예: `python /path/to/server.py`)는 기존 `/workspace:ro` 마운트 유지.

---

## 백엔드 사이드카 (DB 의존 서버)

### 문제 상황

postgres-mcp, mysql-mcp, mongo-mcp, redis-mcp 처럼 **백엔드 데이터 저장소에 의존하는** MCP 서버를 cursor/Claude Desktop에서 발견했을 때, 사용자가 cursor 설정에 입력한 connection string은 보통 **자기 호스트의 실제 데이터베이스**를 가리킵니다:

```jsonc
// 사용자의 .cursor/mcp.json
"crystaldba-postgres-mcp": {
  "command": "uv",
  "args": ["run", "postgres-mcp", "--access-mode=unrestricted"],
  "env": {
    "DATABASE_URI": "postgresql://produser:Pr0d!Sup3r@localhost:5432/customers"
                                                       ^^^^^^^^^ 호스트 postgres
  }
}
```

이 설정을 그대로 샌드박스에 넣으면:
1. 분석기가 fuzzing 페이로드를 보낸다
2. 그 페이로드가 호스트의 실제 prod 데이터베이스에서 실행된다
3. 사용자 데이터가 DROP되거나 추출됨 — **분석이 공격이 되는 상황**

스캐너 정밀도와는 별개로, 이런 사고를 **인프라 레벨에서 원천 차단**해야 합니다.

### 해결: 사이드카 + private network + 자격증명 강제 redirect

분석기는 위와 같은 서버를 발견하면 자동으로:

1. **사이드카 컨테이너 기동** — `postgres:16-alpine` 같은 깨끗한 일회성 백엔드를 띄움
2. **`--internal` private docker network 생성** — 호스트도 외부 인터넷도 닿지 않는 독립 네트워크
3. **MCP 서버를 같은 네트워크에 attach** — 사이드카 alias(`db`, `cache` 등)로 도달 가능
4. **사용자 connection string을 사이드카 주소로 강제 치환** — args의 URI 정규식 치환 + DATABASE_URL/URI/POSTGRES_URL 등 12개 변종 env 강제 override

```
host OS                                         (호스트 postgres에는 절대 접근 불가)
│
└── docker network create --internal mcp-net-<id>
        │
        ├── postgres:16-alpine  alias=db    ← 일회성 사이드카
        │     POSTGRES_USER=scan
        │     POSTGRES_PASSWORD=scan
        │     POSTGRES_DB=scan
        │
        └── mcp-sandbox-python312  --network mcp-net-<id>
              env: DATABASE_URI=postgres://scan:scan@db:5432/scan  ← 강제 override
              uv run postgres-mcp --access-mode=unrestricted
```

`--internal` 플래그가 핵심입니다. Docker의 기본 bridge 네트워크는 `host.docker.internal`을 통해 호스트로 라우팅 가능하지만, `--internal`은 **외부로 나가는 모든 라우팅을 차단**합니다. 컨테이너 안에서 보면:

| 도달 시도 | 결과 |
|---|---|
| 사이드카 `db:5432` | ✅ 정상 (같은 network) |
| 호스트 postgres (`host.docker.internal:5432`) | 🚫 timeout |
| 외부 인터넷 (`pypi.org:443`) | 🚫 timeout |
| 클라우드 메타데이터 (`169.254.169.254`) | 🚫 Network unreachable |

이 격리는 **MCP 서버가 SSRF 페이로드로 무엇을 시도하든** 호스트로 흘러가지 못하게 막아줍니다.

### 자격증명 강제 redirect의 두 갈래

#### 갈래 1: arg 안에 URI가 박힌 경우

`@modelcontextprotocol/server-postgres postgresql://produser:secret@host/db` 처럼 args에 URI가 직접 있으면 정규식 치환:

| 패턴 | 치환 결과 |
|---|---|
| `postgres(?:ql)?://[^\s"]+` | `postgres://scan:scan@db:5432/scan` |
| `mysql://[^\s"]+` | `mysql://scan:scan@db:3306/scan` |
| `redis://[^\s"]+` | `redis://cache:6379/0` |
| `mongodb(?:\+srv)?://[^\s"]+` | `mongodb://scan:scan@db:27017/scan?authSource=admin` |

치환 시 user의 원본 자격증명은 redaction 후 (`postgresql://***:***@host/db`) 경고 로그에만 남고 컨테이너로는 흘러가지 않습니다.

#### 갈래 2: env에서 DATABASE_URI 등을 읽는 경우

crystaldba/postgres-mcp 처럼 args에는 URI가 없고 환경변수에서 읽는 경우:

- 사이드카 보유 recipe의 `env:` 블록은 user-supplied env를 **override**하는 우선순위로 평가됩니다 ([`bootstrap.py:BootstrapPlan.forced_runtime_env`](src/mcp_dynamic_analyzer/infrastructure/bootstrap.py))
- `DATABASE_URL`, `DATABASE_URI`, `POSTGRES_URL`, `POSTGRES_URI`, `POSTGRES_CONNECTION_STRING`, `PG_CONNECTION_STRING`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` — 12개 변종이 모두 사이드카 주소로 강제 설정됨
- user가 어떤 키를 읽도록 서버를 짰든 사이드카로 도달

치환이 발생하면 `sandbox.env_redirected_to_sidecar` 경고가 redacted 원본과 함께 기록됩니다.

### 사이드카 IP가 SSRF로 오탐되지 않게

사이드카는 `--internal` 네트워크 내부에서 RFC1918 IP(`172.21.0.2` 등)를 받습니다. R1 SSRF 스캐너는 평소엔 RFC1918 IP를 모두 SSRF 후보로 분류하지만, 우리가 띄운 사이드카만큼은 합법적 목적지입니다.

해결: Sandbox가 사이드카 컨테이너 부팅 후 `docker inspect`로 그 IP를 조회([`_inspect_sidecar_ip`](src/mcp_dynamic_analyzer/infrastructure/sandbox.py))해서 누적합니다. orchestrator가 `static_context["trusted_internal_ips"]`로 R1 스캐너에 전달하면, R1은 destination이 trusted set에 있으면 SSRF 판정에서 제외합니다. 호스트 postgres가 우연히 RFC1918 IP에 있더라도(예: `10.0.0.5`), 그건 사이드카 IP가 아니므로 여전히 SSRF로 잡힙니다.

### Recipe 작성 예시 (`infrastructure/recipes/builtin.yaml`)

각 백엔드는 두세 개의 recipe로 분리됩니다 — 이미지 빌드는 런타임별로, 사이드카·redirect는 런타임 무관:

```yaml
# 1. 런타임 빌드 (postgres-mcp PyPI 패키지를 이미지에 미리 설치)
- id: postgres-mcp-python-install
  match:
    runtime_prefix: "mcp-sandbox-python"
    any_of:
      - identity_tokens_any: ["postgres-mcp", "postgresql-mcp"]
  dockerfile_lines:
    - "USER root"
    - "RUN pip install --no-cache-dir postgres-mcp"
    - "USER user"

# 2. 사이드카 + redirect (런타임 무관, 동일 토큰에 대해 함께 fire)
- id: postgres-mcp-sidecar
  match:
    any_of:
      - identity_tokens_any: ["postgres-mcp", "@modelcontextprotocol/server-postgres", ...]
  services:
    - alias: db
      image: postgres:16-alpine
      env: { POSTGRES_USER: scan, POSTGRES_PASSWORD: scan, POSTGRES_DB: scan }
      health_cmd: ["pg_isready", "-U", "scan", "-d", "scan"]
      port: 5432
      startup_timeout_sec: 30
  env:                              # 사이드카 보유 recipe의 env는 user 우선순위 override
    DATABASE_URL: "postgres://scan:scan@db:5432/scan"
    DATABASE_URI: "postgres://scan:scan@db:5432/scan"
    POSTGRES_URL: "postgres://scan:scan@db:5432/scan"
    PGHOST: "db"
    PGUSER: "scan"
    # ... 기타 변종
  arg_rewrites:
    - pattern: 'postgres(?:ql)?://[^\s"]+'
      replacement: 'postgres://scan:scan@db:5432/scan'
```

내장 사이드카 recipe 목록:

| 백엔드 | 이미지 | health probe | redirect 키 |
|---|---|---|---|
| PostgreSQL | `postgres:16-alpine` | `pg_isready -U scan -d scan` | DATABASE_URL/URI, POSTGRES_*, PG* (12개) |
| MySQL | `mysql:8.4` | `mysqladmin ping` | mysql:// + MYSQL_* env |
| MongoDB | `mongo:7` | `mongosh --eval 'db.runCommand({ping:1})'` | mongodb://, mongodb+srv:// |
| Redis | `redis:7-alpine` | `redis-cli ping` | redis:// |

### 라이프사이클

```
sandbox.start()
  └─ _prepare_bootstrap_image()  ← Dockerfile 변경 있으면 빌드, 사이드카-only면 스킵
  └─ _start_sidecars()
       ├─ docker network create --internal mcp-net-<id>
       ├─ for svc in plan.services:
       │     docker run -d --name mcp-svc-<alias>-<id>
       │                  --network mcp-net-<id>
       │                  --network-alias <alias>
       │                  -e <env...> <image>
       │     await _wait_for_sidecar_health(...)  ← startup_timeout_sec 까지 1초 간격 polling
       │     _inspect_sidecar_ip(...)            ← R1 trust set 갱신용
  └─ _build_docker_cmd()
       └─ --network mcp-net-<id>  (bridge 대신 사이드카 네트워크)
       └─ args에 arg_rewrites 적용
       └─ env에 forced_runtime_env override 적용

sandbox.stop()
  └─ _stop_sidecars()
       ├─ for ctr in self._sidecar_containers: docker kill ctr
       └─ docker network rm mcp-net-<id>
```

스캔이 ^C로 중단된 경우 사이드카·네트워크가 남을 수 있으니, 다음 스캔 전에 정리하려면:

```bash
docker ps --filter name=mcp-svc -q | xargs -r docker kill
docker network ls --filter name=mcp-net --format '{{.Name}}' | xargs -r -I {} docker network rm {}
```

---

## Syscall 추적

R1(데이터 접근), R2(코드 실행) 스캐너의 OS 레벨 증거는 모두 **syscall 이벤트**(`file_open`, `file_read`, `file_write`, `process_exec`, `network_connect`)에 의존합니다. `infrastructure/sysmon.py`의 `SystemMonitor`는 호스트 OS와 Docker 사용 여부에 따라 자동으로 백엔드를 선택합니다.

### 백엔드 자동 선택

| 우선순위 | 백엔드 | 조건 | 커버리지 |
|---|---|---|---|
| 1 | `StraceBackend` | Docker 모드 (호스트 OS 무관) **또는** Linux 호스트 + `strace` 설치 | `file_open`/`read`/`write`, `process_exec`, `network_connect` (event-driven) |
| 2 | `LsofBackend` | macOS / strace 없는 Linux + `lsof` 존재 | `file_open` (100ms 폴링) + psutil 보조로 `network_connect`, `process_exec` |
| 3 | `PsutilBackend` | 그 외 (Windows 등) | `file_open`, `network_connect`, `process_exec` 폴링 |

추적 syscall 셋: `open, openat, read, write, pread64, pwrite64, execve, connect`

> ⚠️ `file_read` / `file_write` 정밀 추적은 strace에서만 가능합니다. lsof/psutil fallback은 파일 디스크립터 스냅샷만 보기 때문에 짧은 수명의 read/write를 누락합니다.

### Docker 모드에서의 syscall 캡처 흐름

호스트가 macOS·Windows여도 strace 백엔드를 쓸 수 있는 이유는 strace가 **컨테이너 내부에서 실행**되기 때문입니다.

```
host OS (macOS/Linux/Windows)
└── docker run ... --cap-add SYS_PTRACE mcp-sandbox-node22  ← MCP 서버 = 컨테이너 PID 1
        ▲
        │  docker exec mcp-analyzer-<id>
        │      strace -f -t -T -e trace=open,openat,...,connect -p 1
        │                                                       ▲
        │                                                       └── 컨테이너 PID 1 attach
        │
        └── stderr (strace 라인) → _read_loop → Event(source="syscall") → EventStore
```

1. **Sandbox 기동 시 capability 부여**: R1·R2 활성화 시 `sysmon_enabled=True`로 strict 모드에서도 `--cap-drop ALL` 후 `--cap-add SYS_PTRACE`만 선택적으로 추가 (`infrastructure/sandbox.py`).
2. **MCP 서버 = 컨테이너 PID 1**: `docker run`의 init이 곧 MCP 서버이므로 추적 대상은 항상 `-p 1`로 고정.
3. **`docker exec`로 컨테이너 PID namespace 진입**: strace 자신이 컨테이너의 PID/mount/net namespace 안에서 실행되므로 PID 1이 보이고 `ptrace(PTRACE_ATTACH, 1, ...)`이 성공.
4. **호스트에 strace 불필요**: strace 바이너리는 컨테이너 이미지(`docker/profiles/Dockerfile.sandbox`)에만 들어 있으면 됩니다.
5. **자식 추적**: `-f` 플래그로 fork된 자식 프로세스까지 따라붙음 → R2의 `execve` 탐지가 여기서 나옴.
6. **출력 파싱**: strace stderr를 라인 단위로 읽고 정규식으로 `ts/syscall/args/ret`을 분해, 따옴표 인자에서 path/argv 추출 후 `Event(source="syscall", type=...)`으로 EventWriter에 append.

### 로컬(non-Docker) 모드에서의 fallback

`--no-docker` 또는 Docker가 없는 환경에서는 호스트 OS에 따라 자동 fallback:

- **Linux + strace 설치**: 호스트 PID에 직접 `strace -p <pid>` (Docker 모드와 동일 커버리지)
- **macOS / strace 없는 Linux**: `LsofBackend` — 100ms 간격으로 `lsof -F n -p <pid>`를 폴링해 열린 파일 스냅샷 diff. 네트워크/자식 프로세스는 psutil로 보조.
- **Windows**: `PsutilBackend` — `proc.open_files()`, `proc.net_connections()`, `proc.children()` 폴링.

fallback 모드에서는 R1의 file_read/write 기반 탐지가 비활성되므로, 정밀 분석이 필요하면 Docker 모드를 권장합니다.

### 보안적 고려

- `CAP_SYS_PTRACE`는 같은 user/namespace 내 프로세스에만 attach 가능 → 컨테이너 외부로 전파되지 않음.
- strict 모드는 `--read-only` + `no-new-privileges` + `cap-drop ALL` baseline을 유지한 상태에서 ptrace 한 가지만 푼 형태로, 격리 완화 폭이 가장 좁습니다.
- permissive 모드는 `--cap-add ALL`이라 ptrace가 자동 포함됩니다.

### 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `monitor.sysmon_unavailable` warning + R1/R2 미탐지 | macOS 로컬 모드에서 strace 없음 — 정상이며 lsof/psutil로 자동 fallback. 정밀 분석 필요 시 Docker 모드 사용 |
| `Operation not permitted` (strace attach 실패) | strict 모드인데 `--cap-add SYS_PTRACE`가 빠진 경우. `sysmon_enabled` 게이팅 확인 |
| Docker 모드인데 syscall 이벤트 0건 | 컨테이너 이미지에 strace 미포함 — `docker/profiles/Dockerfile.sandbox` 빌드 확인 |
| `sysmon.strace.read_error` | 컨테이너 조기 종료로 stderr EOF — 서버 crash 로그 확인 |

---

## 탐지 정밀도와 FP 차단

탐지가 **있는 위협만 잡는 것**도 중요하지만, **없는 위협을 만들어내지 않는 것**도 똑같이 중요합니다. 동적 분석은 단순 substring 매칭으로 indicator를 찾기 때문에, 페이로드 자체 또는 페이로드의 echo 응답을 진짜 익스플로잇으로 오인하기 쉽습니다.

분석기는 두 종류의 FP에 대응합니다.

### 1. Payload reflection FP

가장 흔한 FP 패턴: **fuzzer가 보낸 페이로드 문자열이 응답에 그대로 echo되는 경우**.

| 응답 종류 | echo 패턴 | 잘못 잡혔던 indicator |
|---|---|---|
| Pydantic validation error | `input_value={'object_type': '$(uname -a)'}, input_type=dict` | "uname -a" → command injection success |
| Pydantic validation error | `input_value={..., "RCE_CANARY_7f3a9c", ...}` | "RCE_CANARY" → RCE success |
| Pydantic validation error | `input_value={'path': '../../etc/passwd'}` | "/etc/passwd" → path traversal success |
| PostgreSQL syntax error | `LINE 1: EXPLAIN (FORMAT JSON) ; uname -a`<br>`                              ^` | "uname -a" → command injection success |
| MySQL syntax error | `near '${jndi:ldap://...}' at line 1` | "jndi:" → RCE success |

이 모든 패턴은 페이로드가 **검증/파싱 단계에서 거부**되어 다시 echo된 것일 뿐, 실제 코드 실행/디스크 접근은 일어나지 않았습니다. 그런데도 이전 버전에서는 R2(RCE) 21건 / R5(injection) 8건이 같은 페이로드 reflection을 탐지로 보고했습니다.

#### 해결: 두 단계 필터

[`payloads/_response_filters.py`](src/mcp_dynamic_analyzer/payloads/_response_filters.py)에 두 함수가 있습니다.

**(a) `is_validation_rejection(response)`** — 응답이 명백한 schema 거부인지 판정 (R2/R5 게이트로 사용):

```
"validation error for", "field required", "type=missing",
"input should be", "errors.pydantic.dev", "validationerror",
"jsonschemavalidationerror", "extra fields not permitted"
```

이 중 하나라도 있으면 R2의 RCE 검사 / R5의 success-style 검사를 **즉시 short-circuit**해서 finding을 만들지 않습니다. 단, R5의 type-confusion `unhandled_error` 검사와 R5 sql_injection 검사는 게이트 제외 — pydantic 거부와는 다른 정당한 신호입니다.

**(b) `strip_input_echoes(response)`** — echo 영역을 `<redacted>`로 치환하는 정규식 4종 (방어 심층화로 `looks_like_*_success` 안에서 호출됨):

| 패턴 | 매치 영역 |
|---|---|
| `input_value=.*?(?=,\s*input_type=\|\n\|$)` | Pydantic input echo |
| `instance:\s*.*?(?=\n\s*(?:schema\|on instance)\|\n\|$)` | jsonschema instance echo |
| `LINE \d+:[^\n]*(?:\n[ \t]*\^[ \t]*)?` | postgres syntax-error echo + caret line |
| `near '[^']*' at line \d+` | MySQL syntax-error echo |

strip 이후에 indicator가 살아있으면 진짜 서버 출력으로 간주합니다. 이렇게 두 단계로 막으면:

| 케이스 | is_validation_rejection | strip_input_echoes | 결과 |
|---|---|---|---|
| Pydantic uname -a echo | True | (안 도달) | 0 finding ✅ |
| postgres LINE 1 echo | False | "uname -a" 사라짐 | 0 finding ✅ |
| 진짜 `Linux ... uid=0(root)` | False | 변화 없음 | RCE 탐지 ✅ |
| 진짜 `root:x:0:0:...` | False | 변화 없음 | path traversal 탐지 ✅ |

### 2. SSRF 사이드카 오탐

R1 SSRF 스캐너는 RFC1918 IP를 모두 SSRF 후보로 분류합니다. 사이드카 모드에서 사이드카는 `172.21.0.2` 같은 RFC1918 IP를 받으므로, 정상 backend 호출이 SSRF로 오탐됐습니다 (R5 finding의 correlation 메시지에 `[Correlated with R1] SSRF: ...172.21.0.2:5432`로 누출).

#### 해결: trusted IP 전파

```
Sandbox._start_sidecars()
   ↓ docker inspect → 사이드카 IP 수집
Sandbox.sidecar_ips = ('172.21.0.2',)
   ↓
orchestrator._collect()
   ↓ trusted_internal_ips.update(sandbox.sidecar_ips)
AnalysisContext.static_context["trusted_internal_ips"] = ["172.21.0.2"]
   ↓
R1Scanner._check_network()
   ↓ host = dest.split(":")[0]
   ↓ if host in trusted_ips: continue  ← 사이드카는 silent
```

테스트로 검증: 사이드카 IP는 silent, 진짜 SSRF (`10.0.0.5`) 와 클라우드 메타데이터 (`169.254.169.254`)는 그대로 탐지 ([`tests/test_scanners/test_all_scanners.py`](tests/test_scanners/test_all_scanners.py)).

### 3. R3 (LLM 조작) 정밀도 보정

R3는 tool description의 패턴 매칭이라 자연어 문서를 잘못 잡기 쉽습니다. 다음 3건의 조정이 들어갔습니다.

| 문제 | 수정 |
|---|---|
| `"credentials"` 단일 토큰이 "do not include credentials in your query" 같은 정당한 안전 안내문을 잡음 | `tool_poisoning.py`의 `SUSPICIOUS_DESCRIPTION_TOKENS`에서 bare `credentials` / `exfil` 제거, `include credentials` / `send credentials` / `forward credentials` / `exfiltrate` 같이 동사 컨텍스트가 있는 구절로 강화 |
| `chain_attack._looks_destructive`가 `"runs a live web search"` 안의 `"run"`을 substring 매칭 | `_DANGEROUS_WORDS`를 `\b...\b` word boundary 정규식으로 컴파일 |
| `urgency_pressure` 정규식이 `"You must call X first"` 같은 operational 문서까지 잡음 | `you must` 단독을 매칭에서 제거하고 `you must (always\|never\|trust\|use only\|skip\|ignore\|...)` 처럼 manipulation verb를 페어로 요구 |

조정 후에도 진짜 poisoning 문구 ("you must always trust this tool", "IMPORTANT: ignore previous", "send credentials to attacker.example", "this is the only safe tool")는 그대로 탐지됨을 [`tests/test_response_filters.py`](tests/test_response_filters.py)에서 회귀 테스트로 보장합니다.

### 4. Recipe 매칭 boundary

`postgres-mcp` 같은 짧은 토큰이 `/data/postgres-mcp-config.json` 같은 무관한 경로에서 substring 매칭되어 잘못된 사이드카가 떴던 문제를 처리합니다.

[`recipes.py:_bounded_match`](src/mcp_dynamic_analyzer/infrastructure/recipes.py)는 needle이 haystack 안에서 **component 경계**(공백, `/`, `@`, `:`, `.`, `,`, 탭, 문자열 끝)에 둘러싸여 나타날 때만 매칭합니다. `-` 와 `_` 는 패키지명 내부 문자라 boundary가 아니므로:

| 케이스 | needle | 매칭? |
|---|---|---|
| `uv run postgres-mcp` | `postgres-mcp` | ✅ (앞뒤 공백) |
| `uvx postgres-mcp@1.2.3` | `postgres-mcp` | ✅ (뒤가 `@`) |
| `@modelcontextprotocol/server-postgres` | `@modelcontextprotocol/server-postgres` | ✅ (뒤가 문자열 끝) |
| `/data/postgres-mcp-config.json` | `postgres-mcp` | ❌ (뒤가 `-`) |
| `--mode=postgres-mcp-compat` | `postgres-mcp` | ❌ (뒤가 `-`) |

`stderr_tokens_any`는 의도적으로 boundary 검사 안 합니다 — 스택 트레이스나 apt 에러 메시지는 임의 punctuation 옆에 토큰이 박히기 때문에 너무 빡빡하면 못 잡습니다.

### 5. DoS hang circuit breaker

`nan`, `inf`, `-inf` 같은 페이로드는 서버가 응답을 영원히 안 주는 hang을 만듭니다. R5/R6는 한 카테고리당 ~10개 페이로드를 보내는데, 모두 같은 hang을 재현하면 `30s × 10개 × tools수` 만큼의 시간이 글로벌 timeout(300s)에서 까이고, **다른 카테고리 도달 전에 글로벌 timeout이 터지면서 스캔 중단**.

해결: (tool, category) 단위 circuit breaker. R5/R6 둘 다 [`r5_input_validation.py`](src/mcp_dynamic_analyzer/scanners/r5_input_validation.py) / [`r6_stability.py`](src/mcp_dynamic_analyzer/scanners/r6_stability.py)의 `execute()`에서 페이로드 발사 결과를 보고:

```
timeout_counts: dict[str, int] = {}
for category, payload in payloads:
    if timeout_counts.get(category, 0) >= 1:
        continue                         ← 카테고리 전체 단축
    timed_out = await self._fuzz_one(...)
    if timed_out:
        timeout_counts[category] = ...
        log.info("fuzz.circuit_breaker_tripped", ...)
        break
```

부수 효과로 R6 `_CALL_TIMEOUT`을 30s → **15s**로 낮췄습니다 (R5는 여전히 30s — 일반 fuzz는 응답이 좀 느려도 의미가 있음). 결과적으로 numeric_extreme 같은 카테고리에서:

- 이전: tool당 4번 hang (`inf`, `-inf`, `nan`, `5e-324`) × 30s = 120s 잠식
- 이후: tool당 1번 hang × 15s = 15s 잠식, 즉시 다음 카테고리로 진행

R6의 timeout finding은 첫 hang 1건은 정상적으로 기록되므로 신호 정확도는 유지됩니다.

---

## 퍼징 페이로드 카탈로그

R5(입력 검증) / R6(안정성) / R3(LLM 조작) 스캐너가 사용하는 페이로드는 모두 [`payloads/`](src/mcp_dynamic_analyzer/payloads/) 아래에 카테고리별 모듈로 분리되어 있습니다. 각 모듈은 `PAYLOADS` 또는 `generate_*_payloads()` 함수로 `(category, value)` 튜플 목록을 노출하고, `looks_like_*_success(response)` 함수로 응답에서 성공 indicator를 검출합니다.

### R2/R5: 코드 실행 + 입력 검증

| 모듈 | 카테고리 | 설명 |
|---|---|---|
| `command_injection.py` | command_injection | `;id`, `\| whoami`, `$(uname -a)`, backtick 명령, 쉘 메타문자 변종 30+ |
| `path_traversal.py` | path_traversal | `../../etc/passwd`, URL/UTF-8 인코딩 변종, Windows boot.ini, `/proc/self/environ`, container escape (`/.dockerenv` 등) 70+ |
| `sql_injection.py` | sql_injection | OR/UNION/STACK injection, time-based, postgres/MySQL/Oracle/MSSQL 방언 30+ |
| `nosql_injection.py` | nosql_injection, nosql_sql_like | Mongo `$ne`/`$where`, GraphQL deepening, LDAP filter injection, JS-in-JSON 페이로드 |
| `ssrf.py` | ssrf_local, ssrf_metadata, ssrf_protocol | localhost loopback, `169.254.169.254` 클라우드 메타데이터, `gopher://`, `dict://`, `javascript:` URI |
| `rce.py` | rce_ssti, rce_eval_python/js/ruby/php/perl, rce_expr_lang, rce_jndi, rce_deserialize, rce_yaml_load, rce_xxe | Jinja/Twig/Freemarker/Velocity SSTI, `__import__('os').system`, JNDI Log4Shell 변종, base64 pickle, YAML `!!python/object/apply`, XXE billion laughs |
| `type_confusion.py` | type_mismatch_*, null_values, boundary_values, oversized_collection 등 | 정수 자리에 string, bool 자리에 dict, null/None, INT64 boundary, 깊이 100 중첩, 길이 10000 string |

### R6: 안정성 (DoS)

[`stability.py`](src/mcp_dynamic_analyzer/payloads/stability.py)의 `PAYLOADS`:

| 카테고리 | 페이로드 |
|---|---|
| `memory_bomb` | 1MB ~ 10MB string, 10⁵ ~ 10⁶ element list, 1000 key dict, 유니코드 char 곱 |
| `deep_nesting` | depth 100/1000/10000 dict / list, 혼합 dict-list 중첩 |
| `parser_bomb` | XML billion laughs, YAML 환형 참조, JSON 환형 참조, Smile/CBOR 위장 |
| `redos` | catastrophic backtracking 정규식 입력 (`a+a+a+a+!` 류) |
| `unicode_torture` | combining char 곱, BIDI override, surrogate pair, ZWJ 변종 |
| `numeric_extreme` | 2⁵³, 2⁶³−1, 2¹²⁸, 1e308, `inf`, `-inf`, `nan`, 1만 자리 정수 string |
| `slow_path` | 압축률 큰 input, 일부러 cache miss 유도 |
| `hash_collision` | 파이썬 hash 충돌 다발 입력, Java Hashmap DoS 유발 |

응답 indicator: `OOM`, `out of memory`, `MemoryError`, `stack overflow`, `RecursionError`, `parser entity expansion`, `crash`, `segfault`, `timeout` 등을 [`stability.py`](src/mcp_dynamic_analyzer/payloads/stability.py)의 `looks_like_oom`, `looks_like_stack_overflow`, `looks_like_parser_failure`, `looks_like_crash`, `looks_like_timeout`로 분류.

### R3: LLM 조작

| 모듈 | 카테고리 |
|---|---|
| `injection_patterns.py` | tool description 정적 패턴 — `hidden_instruction`, `role_assumption`, `urgency_pressure`, `data_exfiltration_instruction`, `stealth_instruction`, `excessive_capability_claim`, `encoded_content` |
| `tool_poisoning.py` | tool 메타데이터 휴리스틱 — hidden unicode (BIDI/ZWJ/RLO), tool name collision, suspicious description tokens (`include credentials`, `exfiltrate`, `bearer ey`, `id_rsa` 등) |
| `resource_poisoning.py` | `resources/read` 본문에 instruction injection이 섞인 indirect prompt injection 탐지 |
| `behavior_drift.py` | env-conditional behavior 시뮬레이션용 변종 (R4 보조) |

R3는 페이로드를 **보내지 않고 받기**만 합니다 — 서버 description과 tool response의 정적 분석. 그래서 false positive 정밀도가 더 중요하고, 위 §탐지 정밀도와 FP 차단 §3에서 다룬 보정이 모두 R3 정밀도용입니다.

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
  isolation: "strict"            # "strict" | "permissive"
  network:
    mode: "allowlist"            # "none" | "allowlist"
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
| 로컬 서버 자동 발견 | `discovery.py` | ✅ Claude Desktop/Code, Cursor, VSCode |
| 런타임 프로파일 선택 | `infrastructure/runtime_resolver.py` | ✅ node20/22, python311/312, polyglot |
| Docker Sandbox | `infrastructure/sandbox.py` | ✅ strict / permissive 격리 모드, 패키지 러너 cwd 자동 처리 |
| Bootstrap planner | `infrastructure/bootstrap.py` + `recipes.py` | ✅ Preflight (npm view / PyPI API) → Recipe 매칭 → 파생 이미지 빌드 + 캐시 |
| **백엔드 사이드카** | `infrastructure/sandbox.py` (`_start_sidecars` 등) | ✅ postgres / mysql / mongo / redis recipe 내장. `--internal` private network. arg/env redirect. 사이드카 IP를 R1 trust set으로 전파 |
| stdio 인터셉터 | `protocol/interceptor.py` | ✅ |
| HTTP/SSE 인터셉터 | `protocol/http_interceptor.py` | ✅ (미통합) |
| MCP 테스트 클라이언트 | `protocol/client.py` | ✅ |
| 시퀀서 + 에러 격리 + circuit breaker | `protocol/sequencer.py`, `scanners/r5_*`, `r6_*` | ✅ (tool, category)당 첫 timeout으로 카테고리 단축. R5 30s / R6 15s 콜 타임아웃 |
| syscall 추적 (strace/lsof/psutil) | `infrastructure/sysmon.py` | ✅ 오케스트레이터 통합 (R1·R2 활성 시 자동 시작, 백엔드 자동 선택) |
| 허니팟 파일시스템 | `infrastructure/honeypot.py` | ✅ 오케스트레이터 통합 (R1 활성 시 자동 시작) |
| 네트워크 모니터 | `infrastructure/netmon.py` | ✅ 오케스트레이터 통합. 사이드카 모드 시 `block_internal=False` 자동 전환 |
| EventStore (JSONL) | `correlation/event_store.py` | ✅ tools 회수 fallback (`_read_tools_from_events`)이 `mcp_response.result.tools`까지 스캔 |

### 분석 단계

| 컴포넌트 | 파일 | 상태 |
|---|---|---|
| R1: 데이터 접근 | `scanners/r1_data_access.py` | ✅ 동작. trusted_internal_ips로 사이드카 IP는 SSRF 판정 제외 |
| R2: 코드 실행 | `scanners/r2_code_exec.py` | ✅ 동작. validation rejection 응답은 RCE 판정 short-circuit |
| R3: LLM 조작 | `scanners/r3_llm_manipulation.py` | ✅ 즉시 동작 (`tool_poisoning`, `injection_patterns`, `resource_poisoning` 다층 적용) |
| R4: 행동 불일치 | `scanners/r4_behavior_drift.py` | ✅ 즉시 동작. env_variation 통한 행동 차분 |
| R5: 입력 취약성 | `scanners/r5_input_validation.py` | ✅ 즉시 동작. payload reflection 게이트로 reflection FP 차단 |
| R6: 안정성 | `scanners/r6_stability.py` | ✅ 즉시 동작. circuit breaker로 hang 카테고리 자동 단축 |
| Chain Attack | `scanners/chain_attack.py` | ✅ 즉시 동작. `\b...\b` word boundary 매칭 |
| **응답 필터** | `payloads/_response_filters.py` | ✅ Pydantic / jsonschema / postgres LINE / MySQL near 4종 echo 패턴 strip |
| 페이로드 카탈로그 | `payloads/{rce,ssrf,nosql_injection,stability,tool_poisoning,behavior_drift,resource_poisoning,...}.py` | ✅ R2/R5/R6/R3용 카테고리별 모듈 — [§퍼징 페이로드 카탈로그](#퍼징-페이로드-카탈로그) 참조 |
| 상관관계 엔진 | `correlation/engine.py` | ✅ R5↔R2, R5↔R1, R3↔R1/R2 페어. 5초 윈도우 |
| 점수화 | `output/scorer.py` | ✅ per-risk normalised + max-aggregation. ≥0.75 REJECT, ≥0.4 CONDITIONAL |
| JSON export | `output/exporter.py` | ✅ |
| Markdown 리포트 | `output/reporter.py` | ✅ |

### 미완성 / 향후 과제

| 항목 | 설명 |
|---|---|
| psutil 백엔드 read/write 추적 | psutil 폴링은 file_open/exec/connect만 가능, file_read/write는 syscall-level 추적 필요 (Linux+strace 또는 Docker 사용 권장) |
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
