# 위협 → 페이로드 매핑

각 위협 유형(R1–R6 + chain_attack)이 어떤 페이로드 모듈 / 카테고리로 검증되는지의 전체 인벤토리. 페이로드 신뢰성·커버리지 질문에 답하기 위한 reference.

---

## R1 — Unauthorized Data Access / Exfiltration

- **스캐너**: [`r1_data_access.py`](../src/mcp_dynamic_analyzer/scanners/r1_data_access.py)
- **페이로드 모듈**: 별도 페이로드 없음 — **부수 채널(side channel) 기반**

| 신호원 | 어떻게 잡나 |
|---|---|
| **honeypot** | 스캔 시작 시 sandbox에 가짜 민감 파일(`.env`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `cookies.sqlite`, 워크스페이스 git config) 5개를 미끼로 깔고, 서버가 그걸 `open()`/`read()`/`exec()` 하는지 strace로 감시. 접근 = HIGH/CRITICAL 정탐 |
| **outbound_connection** | 컨테이너에서 신뢰 IP 집합(MCP 서버가 의도적으로 통신하기로 한 호스트, sidecar IP 등) 외로 나가는 connect(2) / 네트워크 이벤트. 외부 유출 시도 = HIGH |

→ R1은 **페이로드를 주입하는 게 아니라 환경을 미끼화**해서 서버 행동을 관찰하는 형태.

---

## R2 — Unauthorized Code / Command Execution

- **스캐너**: R5 `_check`가 RCE 카테고리 응답을 R2로 분류 + R6 일부
- **페이로드 모듈**: [`rce.py`](../src/mcp_dynamic_analyzer/payloads/rce.py) + [`command_injection.py`](../src/mcp_dynamic_analyzer/payloads/command_injection.py)

### `rce.py` — `PAYLOADS` dict

| 카테고리 | 의도 |
|---|---|
| `ssti` | Jinja2 / ERB / Twig 등 Server-Side Template Injection (`{{7*7}}`, `{%...%}`) |
| `eval_python` | `__import__('os').system(...)`, `compile()`, `exec()` |
| `eval_js` | `Function()`, `eval()`, prototype 변조 |
| `eval_ruby` | `instance_eval`, backtick |
| `eval_php` | `assert()`, `system()`, eval |
| `eval_perl` | `qx//`, backticks |
| `expr_lang` | SpEL, OGNL, EL — 자바 표현식 |
| `jndi` | `${jndi:ldap://...}` (Log4Shell 계열) |
| `deserialize` | Java/Python/Ruby/PHP serialized gadget |
| `yaml_load` | PyYAML `!!python/object/apply:os.system` 등 unsafe tag |
| `xxe` | XML External Entity (`<!ENTITY x SYSTEM "file:///etc/passwd">`) |

### `command_injection.py` — `PAYLOADS` 평면 리스트

`BASIC + OBFUSCATED + BLIND + WINDOWS + ENV_SMUGGLE + ENCODED`:

- `;`, `|`, `` ` ``, `$()` 변종
- Windows `&` / `^`
- blind 시간 지연 (`sleep 5`, `ping`)
- 환경변수 smuggling
- base64/hex encoded shell

**탐지**: `rce.looks_like_rce_success(masked)` / `command_injection.looks_like_injection_success(masked)` — 응답에 명령 실행 결과 흔적(`uid=`, `/bin/sh`, 정수 평가 결과 `49`)이 나오면 정탐. R2 CRITICAL 0.9 confidence.

---

## R3 — LLM Behavior Manipulation

- **스캐너**: [`r3_llm_manipulation.py`](../src/mcp_dynamic_analyzer/scanners/r3_llm_manipulation.py)
- **페이로드 모듈**: [`injection_patterns.py`](../src/mcp_dynamic_analyzer/payloads/injection_patterns.py) + [`tool_poisoning.py`](../src/mcp_dynamic_analyzer/payloads/tool_poisoning.py) + [`resource_poisoning.py`](../src/mcp_dynamic_analyzer/payloads/resource_poisoning.py)

R3는 **페이로드를 주입하는 스캐너가 아니라 서버가 LLM에게 보내는 텍스트(도구 description / response / resource)를 검사**하는 스캐너. 그 검사기를 구동하는 패턴 집합:

### `injection_patterns.py` — Regex 패턴 10종

| 패턴명 | 잡는 것 |
|---|---|
| `hidden_instruction` | `<system>`, `[[INST]]`, 숨은 LLM 지시문 |
| `role_assumption` | "You are now ...", "Forget your instructions" |
| `urgency_pressure` | "URGENT", "IMMEDIATE ACTION REQUIRED" |
| `data_exfiltration_instruction` | "Send X to <attacker_url>", "POST credentials to ..." |
| `stealth_instruction` | "Do not mention this to the user" |
| `excessive_capability_claim` | "I can read your private files" — 거짓 권한 주장 |
| `encoded_content` | base64/hex 블록 내부에 명령 |
| `tool_return_instruction` | "now run X", "next call Y" (도구 출력이 LLM에 후속 호출 시키려는 패턴) |
| `hidden_system_prompt` | 응답에 시스템 프롬프트 노출 |
| `markdown_image_exfil` | `![](attacker.com?data=...)` 마크다운 이미지 통한 유출 |

### `tool_poisoning.py` — 도구 정의 자체의 악성 패턴

- `DESCRIPTION_PAYLOADS` / `PARAMETER_DESCRIPTION_PAYLOADS`: tool description에 LLM 지시문이 박혀있는 패턴
- `ENUM_POISON_PAYLOADS`: enum 값에 명령어 박기
- `SHADOW_NAMES`: 다른 도구를 사칭하는 도구 이름
- `HIDDEN_UNICODE_CODEPOINTS`: bidirectional override, zero-width 문자 (Trojan Source)

### `resource_poisoning.py`

- `RESOURCE_BODY_PAYLOADS`: MCP resource body에 들어있을 수 있는 LLM 조작 내용
- `RESOURCE_URI_PAYLOADS`: `file://`, `data:`, `javascript:` 등 의심 URI
- `MIME_CONFUSION_PAYLOADS`: content-type vs 실제 내용 불일치

---

## R4 — Behavioral Inconsistency / Deception

- **스캐너**: [`r4_behavior_drift.py`](../src/mcp_dynamic_analyzer/scanners/r4_behavior_drift.py)
- **페이로드 모듈**: [`behavior_drift.py`](../src/mcp_dynamic_analyzer/payloads/behavior_drift.py) (`PAYLOADS` dict)

페이로드는 도구에 보내는 입력이 아니라 **컨테이너 환경 변수**. 같은 도구 호출을 환경만 바꿔 반복했을 때 응답이 달라지는지 (서버가 "누가 보는지"에 따라 다른 도구 / 다른 내용 노출하는지) 비교:

| 카테고리 | 변경하는 것 | 잡는 것 |
|---|---|---|
| `temporal` | TZ, 날짜 환경변수 | 시간 의존적 응답 차이 |
| `identity` | USER, USERNAME | 사용자 따라 도구 목록 / 응답 달라짐 (rug pull) |
| `locale` | LANG, LC_ALL | 로케일 따라 도구 차이 |
| `environment` | NODE_ENV=production vs dev | 환경 따라 capability 다름 |
| `conversation` | 가짜 conversation_id 헤더류 | 세션별 차이 |
| `feature_flag` | FEATURE_X=1 같은 플래그 | flag 따라 숨겨진 도구 노출 |
| `rate_limit` | rate limit hint 환경 | 무제한 모드 진입 |
| `host_context` | CI, BUILD_NUMBER, GITHUB_ACTIONS | CI에서만 위험한 도구 |

Orchestrator가 컨테이너를 `env_0`, `env_1` 등으로 여러 번 띄우고 `init_enumerate`를 반복 → R4가 응답 diff.

---

## R5 — Input Handling Vulnerabilities

- **스캐너**: [`r5_input_validation.py`](../src/mcp_dynamic_analyzer/scanners/r5_input_validation.py) — `FuzzingSequence`
- **페이로드 모듈**: 7개 모듈

### `type_confusion.py` — `PAYLOADS` dict (12 카테고리)

| 카테고리 | 의도 |
|---|---|
| `null_values` | null, undefined, None, "" |
| `type_mismatch_string` | 문자열 자리에 숫자/배열/객체 |
| `type_mismatch_number` | 숫자 자리에 문자열/NaN/Infinity |
| `type_mismatch_bool` | bool 자리에 "true"/"false" 문자열/0/1 |
| `boundary_strings` | empty, max-size, 단일 문자 |
| `nested_objects` | 객체 안 객체 |
| `json_special` | `Infinity`, `NaN`, `-0`, BigInt |
| `special_strings` | 컨트롤 문자, null byte (`\0`) |
| `encoding_traps` | lone surrogate (`\ud800`), UTF-8 BOM, invalid UTF-8 |
| `id_format` | UUID 자리에 path / SQL |
| `url_format` | http://, file://, javascript: |
| `date_format` | ISO / unix epoch / "yesterday" |

### `sql_injection.py`

평면 `PAYLOADS` 리스트. 클래식: `' OR 1=1--`, `UNION SELECT`, 시간 지연(`'; WAITFOR DELAY '0:0:5'--`), error-based, blind boolean. MySQL/Postgres/MSSQL/Oracle/SQLite 변종.

### `nosql_injection.py` — `PAYLOADS` dict (10 카테고리)

| 카테고리 | 대상 |
|---|---|
| `mongo_operators` | `$ne`, `$gt`, `$where`, `$regex` |
| `mongo_auth_bypass` | `{"$ne": null}` 류 |
| `mongo_blind` | 시간 지연 `$where` |
| `couchdb` | CouchDB 특수 |
| `elasticsearch` | ES script_score, painless |
| `graphql` | introspection, alias 폭격 |
| `ldap` | `*)(uid=*` 류 |
| `redis` | CONFIG/EVAL/CLUSTER |
| `cassandra` | CQL injection |
| `sql_like_nosql` | SQL 모양으로 NoSQL 우회 시도 |

### `path_traversal.py` — 6개 리스트

- `UNIX_PAYLOADS` (`../../../etc/passwd`)
- `WINDOWS_PAYLOADS` (`..\..\..\windows\win.ini`)
- `MACOS_PAYLOADS`
- `CONTAINER_PAYLOADS` (`/proc/self/environ`, `/var/run/secrets/...`)
- `NULL_BYTE_PAYLOADS` (`file.txt%00.png`)
- `ENCODED_PAYLOADS` (URL-encoded, double-encoded)

### `ssrf.py` — `PAYLOADS` dict (10 카테고리)

| 카테고리 | 대상 |
|---|---|
| `cloud_metadata` | AWS `169.254.169.254`, GCP, Azure 메타데이터 endpoint |
| `internal_ip` | `127.0.0.1`, `10.x`, `192.168.x`, `::1` |
| `ip_obfuscation` | dotted-decimal, hex, octal IP |
| `url_scheme` | `file://`, `gopher://`, `dict://` |
| `internal_service` | `localhost:6379`, `localhost:5432` |
| `orchestrator` | Kubernetes API, Docker socket |
| `ci_dev_tools` | Jenkins, GitLab, Drone CI 내부 endpoint |
| `dns_rebind` | 시간차 DNS 재결합 도메인 |
| `redirect_chain` | open redirect 통한 우회 |
| `parser_confusion` | URL 파서 차이 활용 |

### `command_injection.py` / `rce.py`

위 R2 참조. R5 fuzzer가 페이로드를 보내지만, RCE 성공 흔적이 발견되면 R2 risk type으로 분류. error leak만 있고 실행 흔적 없으면 R5 finding으로.

---

## R6 — Service Stability Threats

- **스캐너**: [`r6_stability.py`](../src/mcp_dynamic_analyzer/scanners/r6_stability.py) — `StabilityFuzzingSequence`
- **페이로드 모듈**: [`stability.py`](../src/mcp_dynamic_analyzer/payloads/stability.py) (`PAYLOADS` dict — **구성형(constructive)**)

| 카테고리 | 페이로드 형태 | 노리는 것 |
|---|---|---|
| `memory_bomb` | `_big_string(10**N)`, `["x"] * 10**N` | V8/Python heap OOM, transport layer Buffer.concat O(N²) |
| `deep_nesting` | `_deep_dict(N)`, `_deep_list(N)` | recursion limit, stack overflow, JSON parser stack |
| `redos` | `"a"*N + "!"`, `(a+)+$` 류 catastrophic backtracking 트리거 입력 | regex engine 폭주 |
| `unicode_torture` | lone surrogate `"\ud800"`, 결합문자 누적(`Ź́...`), 이모지 `"😀"*N` | UTF-8/UTF-16 변환 폭주, normalization 실패 |
| `numeric_extreme` | `Infinity`, `NaN`, `2**53`, `-2**53`, JSON `1e1000` | 숫자 파서 / 부동소수 오버플로 |
| `slow_path` | `[10000, 9999, ..., 1]` (역순 정렬용) | 알고리즘 worst-case 트리거 |
| `hash_collision` | 일부러 동일 해시값을 만드는 키 집합 | dict 충돌로 O(N²) 삽입 |
| `json_bomb` | `"[[[[...]]]]"` 깊은 중첩 JSON | JSON 파서 stack overflow |
| `xml_bomb` | billion laughs, quadratic blowup | XML 엔티티 expansion |
| `zip_bomb` | gzip 압축된 거대 페이로드 | 압축 해제 시 OOM |
| `yaml_bomb` | YAML 앵커/별칭 expansion (`&a [*a,*a,...]`) | YAML 파서 expansion |
| `pathological_regex` | 임의의 catastrophic regex 자체를 인자로 | regex 엔진 직접 공격 |
| `schema_bomb` | `{"$ref": "#"}` 순환 참조 | JSON Schema 검증기 무한 루프 |

**탐지 신호**:
- 응답 텍스트에서 `OOM_INDICATORS` / `STACK_OVERFLOW_INDICATORS` / `TIMEOUT_INDICATORS` / `PARSER_FAILURE_INDICATORS` / `CRASH_INDICATORS` 매칭
- `outcome=client_timeout` (서버 응답 없음)
- `server_crash` 이벤트 (프로세스 종료 감지)
- cascade dedup으로 한 stall이 N개 finding으로 부풀려지는 것 방지

---

## chain_attack (보조)

- **스캐너**: [`chain_attack.py`](../src/mcp_dynamic_analyzer/scanners/chain_attack.py)

페이로드 보내는 게 아니라 **도구 메타데이터 정적 분석**. 위험 동사(`delete`, `drop`, `exec`, `install` 등)가 read 의도로 명명된 도구가 아닌 곳에 노출됐는지 검사. R3에 가까우나 별도 처리.

---

## 요약 — 위협별 페이로드 성격

| 위협 | 페이로드 모듈 | 카테고리 수 | 페이로드 성격 |
|---|---|---|---|
| R1 | 페이로드 없음 (honeypot + 네트워크) | — | 부수 채널 관찰 |
| R2 | `rce.py` + `command_injection.py` | 11 + 평면(~수십) | 텍스트 문자열 |
| R3 | `injection_patterns.py` + `tool_poisoning.py` + `resource_poisoning.py` | 10 + 4종 + 3종 | 정규식 + 도구 정의 검사 |
| R4 | `behavior_drift.py` (환경변수) | 8 | 환경 변수 변조 |
| R5 | `type_confusion` + `sql_injection` + `nosql_injection` + `path_traversal` + `ssrf` + `command_injection` + `rce` | 12 + 평면 + 10 + 6 + 10 + ... | 텍스트 + 구조 변형 |
| R6 | `stability.py` | 13 | **구성형 (Python 런타임 생성)** |

---

## 공개 corpus 도입 적합성

페이로드 신뢰성·양에 대한 외부 비판("SecLists 같은 거 쓰면 되지 않냐")에 대한 정리:

| 위협 | 공개 corpus 도입 가능? | 이유 |
|---|---|---|
| **R1** | ❌ | 메커니즘 다름 (honeypot + syscall, 페이로드 무관) |
| **R2** (command_injection / RCE) | ✅ **가치 있음** | SecLists / PayloadsAllTheThings에 mature한 OS별·언어별 변종 풍부 |
| **R3** | ❌ | 우리 정규식 패턴 + 도구 메타데이터 검사가 본질. 공개 corpus는 web app injection용 |
| **R4** | ❌ | 환경 변수 페이로드 — 외부 corpus 없음 |
| **R5** (sql_injection / nosql / path_traversal / ssrf) | ✅ **가치 있음** | DB 엔진별 / OS별 / cloud별 변종이 잘 정제됨 |
| **R6** | ❌ **표현 불가** | 구성형 페이로드. 32자 Python 코드(`["x"] * 1_000_000`)가 5MB 입력을 만들어내는 형태 — 텍스트 파일로 표현 불가능. R6의 정탐 3건이 전부 이 형태로 잡힘 |

**계획**: 빌드타임 vendor 구조(`src/mcp_dynamic_analyzer/payloads/vendored/`) — SecLists / PATTI에서 R2/R5용 페이로드만 sparse-checkout으로 가져와 카테고리에 합치기. R6는 구성형 그대로 유지.

---

## 신뢰성 vs 페이로드 양에 대한 답변

지금까지 잡은 정탐 3건 (`chrome-devtools-mcp` V8 OOM, `mcp` Python SDK lone-surrogate, `n8n-mcp` search_templates hang)은 모두 **R6 구성형 페이로드**에서 나왔습니다. 32자 Python으로 표현된 가설("이 SDK는 입력 크기 제한 안 둘 거다")이 한 방에 SDK-레벨 DoS를 맞춘 결과 — 공개 corpus가 표현 못 하는 형태입니다.

FP 문제는 페이로드 양이 아니라 **응답 해석 로직**의 문제로, 페이로드를 늘리면 incidental keyword 매칭이 비례 증가해 오히려 악화됩니다. 지금까지 추가한 FP 차단 로직(`is_clean_success_envelope`, `strip_payload_echo`, `is_handled_tool_error`, `_check_client_timeouts` cascade dedup, `outcome` 게이트)은 전부 응답 해석 강화이지 페이로드 변경이 아닙니다.

**결론**: 공개 corpus는 R2/R5에서 빌드타임 vendor로 도입하고, R6는 구성형 페이로드 유지. 적재적소.
