# Vulnerability Hunting Agent

> **코드를 읽어 가설을 세우고, PoC를 작성해 Docker 샌드박스에서 직접 실행하는** LLM 에이전트. 실제로 트리거된 버그만 보고합니다.

[**English README**](README.md)  ·  Apache-2.0  ·  Python 3.11+

---

**Anthropic "Project Mythos" 스캐폴드**(파일 단위 병렬 hunter + reviewer 단계)를
공개 접근 가능한 frontier 모델 위에 재구성한 것입니다 — 프리뷰 모델은 필요하지
않습니다.

스캐폴드 자체는 의도적으로 작게(파일당 ~150 LOC) 유지되어 있고, 단순하고
포크하기 쉽도록 설계됐습니다.

---

## File-level 독립 hunt

<p align="center">
  <img src="assets/img/per_file_loop.svg" alt="Per-file loop: Hunters → Clusterer → Reviewer" width="100%">
</p>

상위 랭크 파일마다 독립 hunter 세션을 실행합니다 — fresh context,
히스토리 공유 X.

별도 **Reviewer** 단계가 PoC 를 재실행하고, 재현되지 않으면 group 통째로
drop 합니다. 파일 단위 bound 가 결정론적 coverage 와 깔끔한 병렬화를 만듭니다.

이 세 조각(Hunter · Clusterer · Reviewer) 은 **Mythos 의 빌딩 블록(Ranker ·
Hunters · Reviewer) 을 공개 모델 환경에 맞춰 변형(adapt)** 한 것입니다.

---

## Pipeline

<p align="center">
  <img src="assets/img/three_groups.svg" alt="Three groups: Filter · Hunters · Reviewer" width="100%">
</p>

```
Filter → Rank → Selector → Sandbox Prepare → Hunt (Hunter → Cluster → Review) → Report
```

1. **Filter** — 테스트 / 벤더링된 / 생성 코드 제외 (LLM 미사용).
2. **Rank** — 모든 source file 을 보안 관련도 1–5 점으로 채점.
3. **Selector** — Hunter 가 실행할 파일을 고름.
4. **Sandbox Prepare** — repo 별 Docker 이미지 빌드 (environment 단위 결정론
   install: pip / mvn). 또는 직접 빌드한 custom image 사용 가능.
5. **Hunt** — *파일 당 독립 세션 1개*. 코드를 읽고, grep 하고,
   `/workspace` 에 PoC 를 작성한 뒤 network-isolated Docker 컨테이너에서 실행.
   `network: none`, `/code` read-only, `/workspace` tmpfs.
6. **Cluster** — 같은 파일 내 near-duplicate finding 을 group.
7. **Review** — verdict + CVSS + writeup.
8. **Report** — JSON + Markdown.

각 Hunter는 fresh 세션입니다. 히스토리를 공유하지 않고, 독립 실행의 다양성이
그 자체로 이 도구의 핵심입니다.

---

## Quick start

> **요구사항:** Python 3.11+, Docker, Bedrock 접근 가능한 AWS 자격증명 (Opus 4.7).

```bash
# 1. install
git clone https://github.com/ksgsslee/vulnhunt-agent.git
cd vulnhunt-agent
pip install -e .

# 2. config — template 복사 후 provider/region/key 편집
cp settings.example.toml settings.toml

# 3. credentials (Bedrock 직결: SSO / role / AWS_PROFILE 모두 OK)
aws sso login

# 4. UI 실행
streamlit run src/vulnhunt_agent/app.py
```

사이드바에서: repo (git URL 또는 로컬 경로) 선택 → **Environment** 선택
(예: `python:3.12`, `java:21`) → **Save** → 위에서부터 단계별 실행.

**Troubleshooting** — Bedrock 이 `AccessDeniedException` 를 반환하면 Bedrock
콘솔에서 사용 모델의 액세스를 활성화하세요. 모델 + provider 카탈로그는
[settings.toml](settings.example.toml) 에 있습니다.

<p align="center">
  <img src="assets/img/ui_screenshot.png" alt="Streamlit UI — mid-run" width="90%">
</p>

run 이 끝나면 Final Report 가 group된 finding 을 CVSS 순으로 정렬해 보여주고,
각 행을 펼치면 Reviewer 요약 · CWE / CVSS vector · 샌드박스에서 재현된 PoC 를
포함한 writeup 이 나옵니다.

---

## Configuration

레포 root 에 두 위치, operator 가 직접 편집:

**[settings.toml](settings.example.toml)** (gitignored) —
`settings.example.toml` 에서 복사. **`[[providers]]`** 리스트
(Bedrock 직결, bedrock-mantle, LiteLLM, 사내 OpenAI-compatible proxy
등) + **`[[models]]`** 카탈로그를 모두 담음. model 마다 provider 한 개를
가리킵니다. hunter / reviewer / ranker 모델은 사이드바에서 독립 swap.

**[prompts/](prompts/)** — 모든 프롬프트가 여기:
- `prompts/hunters/python.md`, `java.md` — 광범위한 언어별 review prompt.
- `prompts/rankers/<lang>.md` — 언어별 ranker hint.

이게 전부 — `.env`, `~/.scanner/`, 분산된 config 없음.

---

## Project layout

```
src/vulnhunt_agent/
  agents/        hunter, reviewer, clusterer, queue
  pipeline/      filter → rank → selector → sandbox_prepare → hunt → finalize
  core/          llm, settings, run_store, cvss, events
  ui/            streamlit (sidebar, steps, result_cards, cost)
  sandbox/       Docker executor
  repo/          git/local source resolver
prompts/
  hunters/*.md           # language hunter
  rankers/<lang>.md      # 언어별 ranker hint
settings.example.toml    # settings.toml 의 template (settings.toml 은 gitignored)
```

코드 스타일 ([CLAUDE.md](CLAUDE.md) 참조): 파일당 ~150 LOC, 함수당 ~30 LOC,
구현체가 둘 이상 생기기 전엔 `Protocol` / `ABC` / `Generic` 도입 X, 일어날 수
없는 케이스에 대한 방어적 `try/except` X.

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

질문, 피드백, 또는 확장 detection coverage 관심이 있으시면:
<localhost.detect@gmail.com>.

---

## Further reading

- **Mythos 원문 (Anthropic)** — <https://red.anthropic.com/2026/mythos-preview/>

---

## License

[Apache-2.0](LICENSE)
