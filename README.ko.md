# Vulnerability Hunting Agent

> **코드를 읽어 가설을 세우고, PoC를 작성해 Docker 샌드박스에서 직접 실행하는** LLM 에이전트. 실제로 트리거된 버그만 보고합니다.

[**English README**](README.md)  ·  Apache-2.0  ·  Python 3.11+

---

**Anthropic "Project Mythos" 스캐폴드**(파일 단위 병렬 hunter + reviewer 단계)를
공개 접근 가능한 frontier 모델 위에 재구성한 것입니다 — 프리뷰 모델은 필요하지
않습니다.

---

## 독립 slice hunt

<p align="center">
  <img src="assets/img/per_file_loop.svg" alt="Per-file loop: Hunters → Clusterer → Reviewer" width="100%">
</p>

선택된 모든 파일에 모든 Hunter를 실행하지 않고, 관련 전문 Hunter에게
범위가 제한된 graph slice를 라우팅합니다. 세션끼리 대화 히스토리는 공유하지
않지만 content-addressed 불변 소스 context는 재사용합니다.

별도 **Reproducer**가 각 PoC를 깨끗한 컨테이너에서 두 번 실행합니다.
증거만 읽는 **Reviewer**는 확정·기각하거나 선언형 재현 변형을 요청할 수 있지만
직접 명령을 실행할 수 없습니다. slice 단위 bound가 결정론적 coverage와
깔끔한 병렬화를 만듭니다.

증분 native scan은 정확한 변경 node와 critical signal을 24KB 이하 context로
전달합니다. 모든 target은 `finding`, `no_finding`, `deferred` 중 하나로 끝나야
하며, Reviewer의 선언형 variant는 별도 SQLite lease로 실행된 뒤 자동으로
evidence review에 돌아갑니다.

이 세 조각(Hunter · Clusterer · Reviewer) 은 **Mythos 의 빌딩 블록(Ranker ·
Hunters · Reviewer) 을 공개 모델 환경에 맞춰 변형(adapt)** 한 것입니다.

---

## Pipeline

<p align="center">
  <img src="assets/img/three_groups.svg" alt="Three groups: Filter · Hunters · Reviewer" width="100%">
</p>

```
Filter → C Analysis Graph → Rank → Selector → Sandbox Prepare
       → Hunt (Hunter Portfolio → Dedup/Cluster → Review) → Report
```

1. **Filter** — 테스트 / 벤더링된 / 생성 코드 제외 (LLM 미사용).
2. **C Analysis Graph** — call, parser flow, entrypoint, 위험 sink를 찾고
   감지된 모든 entrypoint/critical sink를 최소 한 slice로 계획 (LLM 미사용).
3. **Rank** — 모든 source file 을 보안 관련도 1–5 점으로 채점.
4. **Selector** — graph 필수 파일과 최상위 rank 파일의 합집합을 선택.
5. **Sandbox Prepare** — repo 별 Docker 이미지 빌드 (environment 단위 결정론
   install/build: pip / mvn / npm / CMake / Make / Meson / Autotools).
   또는 직접 빌드한 custom image 사용 가능.
6. **Hunt** — bounded graph slice별로 lease를 획득한 전문 Hunter 세션을
   실행. 각 Hunter는 공유된 불변 excerpt를 시작 context로 받고 코드를 읽고,
   grep 하고,
   `/workspace` 에 PoC 를 작성한 뒤 network-isolated Docker 컨테이너에서 실행.
   `network: none`, `/code` read-only, `/workspace` tmpfs. C 네이티브 PoC
   바이너리는 분리된 실행 가능 tmpfs인 `/workspace/exec`에 컴파일됩니다.
7. **Dedup / Cluster** — exact duplicate를 fingerprint로 먼저 제거하고
   남은 대표 finding만 의미 기반으로 group.
8. **Review** — evidence citation + CVSS/CWE. High/Critical은 서로 다른
   model/prompt 구성 두 개가 필요.
9. **Report** — consensus를 통과한 canonical JSON + Markdown + SARIF 2.1.0.

각 Hunter는 fresh 세션입니다. 대화 히스토리는 공유하지 않고, snapshot에
묶인 소스 context만 재사용합니다.

---

## Quick start

> **요구사항:** Python 3.11+, Docker, OpenAI Platform API key 또는
> ChatGPT 구독으로 로그인한 Codex CLI.

```bash
# 1. install
git clone https://github.com/sh3rlock93/vulnhunt-agent-next.git
cd vulnhunt-agent-next
pip install -e .

# 2. config
cp settings.example.toml settings.toml

# 3a. 기본 경로: OpenAI Responses API (Platform 과금)
export OPENAI_API_KEY="..."

# 3b. OPENAI_API_KEY가 없을 때 fallback: ChatGPT 구독
codex login
codex login status

# 4. UI 실행
streamlit run src/vulnhunt_agent/app.py
```

사이드바에서: repo (git URL 또는 로컬 경로) 선택 → **Environment** 선택
(예: `python:3.12`, `java:21`) → **Save** → 위에서부터 단계별 실행.

CLI에서 Git diff 기반 계획만 확인하거나 실제 스캔을 실행할 수 있습니다.

```bash
# 영향받은 C 함수, caller/callee, slice, sink 계획만 확인
vulnhunt scan /path/to/repo \
  --base-ref main --head-ref HEAD --plan-only

# --plan-only를 빼면 샌드박스를 준비하고 Hunter까지 실행
vulnhunt scan /path/to/repo \
  --base-ref main --head-ref HEAD
```

증분 모드는 clean working tree이고 checkout된 revision이 `head-ref`와 정확히
일치할 때만 사용합니다. ref 누락, build 변경, C 소스 삭제, header 영향 범위를
안전하게 해석할 수 없는 경우에는 이유를 기록하고 full scan으로 전환합니다.

C 저장소는 `c:gcc-13`을 선택하면 됩니다. Auto prepare가 CMake, Make,
Meson, Autotools 프로젝트를 ASan/UBSan으로 빌드합니다. C/H 파일은
tree-sitter-c로 인덱싱하고 Flex/Bison의 `.l`/`.y`도 랭킹과 파일 간 추적
대상에 포함합니다. 고정된 libcue 벤치마크와 블라인드 검증 절차는
[`docs/milestones/m3-c-native-analysis.md`](docs/milestones/m3-c-native-analysis.md)에
정리되어 있습니다.
결정론적 C graph, coverage 정책, 6개 전문 Hunter, 취약/수정 버전 graph
대조 검증은
[`docs/milestones/m5-c-analysis-graph.md`](docs/milestones/m5-c-analysis-graph.md)에
정리되어 있습니다.

durable worker lease, heartbeat, 만료 task 복구, 부분 reproduction 재개는
[`docs/milestones/m7-resumable-operations.md`](docs/milestones/m7-resumable-operations.md)에
정리되어 있습니다. Signal routing, bounded slice work, hard budget, 공유
context packet, Git diff 증분 스캔은
[`docs/milestones/m8-cost-aware-scheduler.md`](docs/milestones/m8-cost-aware-scheduler.md)에
정리되어 있습니다.

증거 기반 review와 strict export 계약은
[`docs/milestones/m4-evidence-review-reporting.md`](docs/milestones/m4-evidence-review-reporting.md)에
정리되어 있습니다. V2 metadata store가 준비된 경우 다음 명령으로 consensus를
통과한 finding을 내보낼 수 있습니다.

```bash
vulnhunt --db .vulnhunt/state.db export RUN_ID \
  --artifacts .vulnhunt/artifacts \
  --output output
```

기본 `openai_auto` provider는 설정한 key 환경변수를 먼저 확인합니다.
값이 있으면 Responses API를 사용하고, 없으면 로그인된 Codex CLI를
호출합니다. 실행 중 API 오류를 다른 과금 경로로 몰래 전환하지는 않습니다.
CLI fallback은 호출 오버헤드가 커서 로컬 사용에 적합하며 자동화의 기본 경로는
Responses API입니다. Bedrock은 명시적으로 선택할 수 있는 provider로 계속
지원합니다.

<p align="center">
  <img src="assets/img/ui_screenshot.png" alt="Streamlit UI — mid-run" width="90%">
</p>

V2 metadata가 있는 run은 UI에 finding state, evidence 수, Reviewer 수,
consensus도 표시됩니다. Strict export에는 source snapshot, 재현 command/oracle,
evidence ID, CVSS/CWE, Reviewer/policy provenance, 영향받는 code location이
포함됩니다.

---

## Configuration

레포 root 에 두 위치, operator 가 직접 편집:

**[settings.toml](settings.example.toml)** (gitignored) —
`settings.example.toml` 에서 복사. **`[[providers]]`** 리스트
(`openai_auto`, Bedrock 직결, bedrock-mantle, LiteLLM, 사내
OpenAI-compatible proxy 등) + **`[[models]]`** 카탈로그를 모두 담습니다.
secret은 TOML에 넣지 말고 provider의 `api_key_env`로 전달합니다. model마다
provider 한 개를 가리키며 hunter / reviewer / ranker 모델은 사이드바에서
독립 swap할 수 있습니다.

**[prompts/](prompts/)** — 모든 프롬프트가 여기:
- `prompts/hunters/python.md` — 광범위한 Python review prompt.
- `prompts/hunters/c/*.md` — C 전문 Hunter 6개. bounds, lifetime,
  parser-state는 기본 활성화.
- `prompts/rankers/<lang>.md` — 언어별 ranker hint.

dotenv는 자동 로드하지 않습니다. 구독 fallback 인증은 `codex login`에
위임하며 Codex 자격증명 파일을 직접 읽거나 복사하지 않습니다.

---

## Project layout

```
src/vulnhunt_agent/
  analysis/      결정론적 C graph, slice, context, dedup
  agents/        hunter, reviewer, clusterer, queue
  pipeline/      filter → graph → rank → selector → sandbox → hunt → finalize
  core/          llm, settings, run_store, cvss, events
  ui/            streamlit (sidebar, steps, result_cards, cost)
  sandbox/       Docker executor
  repo/          git/local source resolver
  reviewing/     evidence packet, Reviewer agent, consensus
  reporting/     strict policy, Markdown/JSON/SARIF exporter
prompts/
  hunters/*.md           # broad language hunter
  hunters/c/*.md         # C 전문 Hunter portfolio
  rankers/<lang>.md      # 언어별 ranker hint
settings.example.toml    # settings.toml 의 template (settings.toml 은 gitignored)
```

---

## Externally validated findings

이 스캐폴드 단일 run 으로 발견한 취약점:

- **[공개 완료]**
  [GHSA-pjwx-r37v-7724](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724) —
  `langchain-core` (Python), CWE-502, CVSS 8.2 (High)

- **[Public fix]**
  [Django #37170](https://code.djangoproject.com/ticket/37170) —
  `django.views.debug` (Python), exception report filter 의 정보 노출
  (Django 보안팀 acknowledged, 다음 릴리스에 fix 예정)

- **[CVE assignment confirmed]**
  Jenkins core (Java) — CVE 발급 확정; advisory release 는 Jenkins
  LTS 일정에 따라 진행 예정

스캐폴드가 third-party 검증을 통과하는 finding 을 만든다는 증거로만 첨부.

---

## Contact

<localhost.detect@gmail.com>

---

## Further reading

- **Mythos 원문 (Anthropic)** — <https://red.anthropic.com/2026/mythos-preview/>

---

## License

[Apache-2.0](LICENSE)
