# lintai — Project Index

> Offline-first security scanner для AI Agent Skills, MCP servers, IDE plugins (Rust).
> Единая точка входа: все документы проекта со ссылками и описаниями.

---

## Key Decisions (summary)

Краткая сводка принятых решений. Canonical truth lives in repo-local docs and release files, not in research notes.

- **Проект**: lintai — свой проект с нуля; cc-audit (55K LOC, Ryo Ebata) = reference only, НЕ форк
- **MVP v0.1 scope**: `SKILL.md`, `CLAUDE.md`, `.mdc/.cursorrules`, `mcp.json`, **Cursor Plugins**
- **MVP v0.1 targets**: сборка/релиз сразу на всех таргетах (включая Windows и Linux musl)
- **Стек**: Rust monorepo, current v0.1 core in a compact internal workspace
- **Архитектура**: `lintai-api` = stable contract, `lintai-engine` = orchestrator, `lintai-parse` = format parsing, `lintai-adapters` = domain routing/semantics
- **Rules**: current `v0.1` core is native-Rust-first; broader YAML/WASM ecosystem work is later
- **Макросы**: `declare_rule!` macro_rules! (НЕ proc-macro) — Clippy/Oxlint precedent, 6x быстрее компиляции
- **Public contracts**: typed `evidence`, explicit `RuleTier`, `stable_key`, `schema_version = 1`
- **Finding location**: byte-span + (optional/derived) line/col; дедуп через `stable_key`, fingerprint считается на выходе (SARIF/CI)
- **Suppress**: Mandatory rule-id + reason; в Markdown НЕ через HTML comments (attack vector!) → external .lintai/suppress.toml
- **Prefix != Category**: SEC = стабильный namespace, Category = мутабельное поле метаданных
- **CLI contract**: exit codes 0/1/2; Windows ANSI; SIGPIPE-safe; CRLF normalization
- **File discovery**: `ignore` crate (gitignore semantics), symlinks not followed by default
- **Config**: unknown keys = error, `explain-config` обязателен, JSON Schema + SchemaStore
- **Testing/release direction**: `lintai-testing` remains internal in `v0.1`; corpus, sample repos, compat snapshots, release barrier, docs gate, and dry release are already wired
- **Remediation**: `lintai fix` is public CLI surface with safe autofix, message suggestions, and preview-only candidate patch edits
- **Лицензия**: Dual MIT + Apache 2.0

---

## Read Order

### Canonical first

| # | Документ | Что внутри |
|---|----------|-----------|
| 1 | **[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)** | Зафиксированные архитектурные решения и invariants |
| 2 | **[../V0_1_RELEASE_CHARTER.md](../V0_1_RELEASE_CHARTER.md)** | Release contract текущего `v0.1` |
| 3 | **[../ARCH_GAPS.md](../ARCH_GAPS.md)** | Остаточные разрывы до release-ready состояния |
| 4 | **[RELEASE_CHECKLIST_V0_1.md](RELEASE_CHECKLIST_V0_1.md)** | Dry release checklist и certification record для `v0.1` |
| 5 | **[ROADMAP_V0_1.md](ROADMAP_V0_1.md)** | Операционный roadmap и sequence итераций |
| 6 | **[FIXTURE_CONTRACT.md](FIXTURE_CONTRACT.md)** | Контракт для corpus cases и sample repos |
| 7 | **[SECURITY_RULES.md](SECURITY_RULES.md)** | Generated catalog of current shipped security rules |

### Research second

Research files below are reference material. They are useful for background and tradeoff history, but they are not the current source of truth over repo-local canonical docs.

---

## Canonical Docs (`docs/`)

Живые документы проекта `lintai` — обновляются вместе с кодом внутри этого репозитория:

- **[VISION.md](VISION.md)** — Зафиксированное видение продукта (v0.1, дифференциация, стратегия кода и портов)
- **[CREDITS.md](CREDITS.md)** — Таблица: компонент → crate/репо → лицензия → что переносим / как используем
- **[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)** — главный canonical doc по архитектуре
- **[FEATURE_CAPABILITIES_MANIFEST.md](FEATURE_CAPABILITIES_MANIFEST.md)** — Декларирование capabilities для снижения false positives
- **[RULE_QUALITY_POLICY.md](RULE_QUALITY_POLICY.md)** — Политика надёжности правил: детерминизм, контекст, доказательства
- **[SECURITY_RULES.md](SECURITY_RULES.md)** — Сгенерированный canonical catalog текущих security rules и их remediation support
- **[GLOSSARY.md](GLOSSARY.md)** — Единые термины (Claims/Capabilities, stable_key/fingerprint, артефакты)
- **[ROADMAP_V0_1.md](ROADMAP_V0_1.md)** — Операционный roadmap от текущего core к publishable `v0.1`
- **[RELEASE_CHECKLIST_V0_1.md](RELEASE_CHECKLIST_V0_1.md)** — Dry release checklist и certification record
- **[FIXTURE_CONTRACT.md](FIXTURE_CONTRACT.md)** — Контракт для corpus cases и sample repos
- **[PUBLIC_COMPATIBILITY_POLICY.md](../PUBLIC_COMPATIBILITY_POLICY.md)** — Политика совместимости для `lintai-api`, config, JSON и SARIF

## Workspace Meta (вне repo)

Эти файлы живут уровнем выше и относятся к общему `agent_skills` workspace, а не к публичному product contract `lintai`:

- [MEMORY.md](../../MEMORY.md) — Локальные заметки по общему workspace
- [CATALOG.md](../../CATALOG.md) — Сгенерированный каталог skills workspace
- [catalog.json](../../catalog.json) — Machine-readable каталог skills workspace

---

## Code

- **[repo root](../)** — Rust workspace `lintai`
- **[README.md](../README.md)** — Quick start, CLI и product contract
- **[V0_1_RELEASE_CHARTER.md](../V0_1_RELEASE_CHARTER.md)** — Зафиксированный релизный контракт `v0.1`
- **[ARCH_GAPS.md](../ARCH_GAPS.md)** — Остаточные разрывы до release-ready `v0.1`

---

## Research — Key Documents

Основные документы по проекту (`../../research/`):

- **[IMPORTANT_BEFORE_START.md](../../research/IMPORTANT_BEFORE_START.md)** — ранний pre-code checklist
- **[LINTAI_PLAN.md](../../research/LINTAI_PLAN.md)** — ранний implementation plan
- **[TECHNICAL_DECISIONS.md](../../research/TECHNICAL_DECISIONS.md)** — historical technical decision log
- **[ARCHITECTURE_BRIEF.md](../../research/ARCHITECTURE_BRIEF.md)** — historical architecture summary
- [EXECUTIVE_SUMMARY.md](../../research/EXECUTIVE_SUMMARY.md) — Rust vs Go сравнение, обоснование выбора Rust
- [README.md](../../research/README.md) — Навигация по research/
- [SOURCES.md](../../research/SOURCES.md) — Все источники исследования

---

## Research — Market & Competitors

- `[start]` **[COMPETITOR_ANALYSIS.md](../../research/COMPETITOR_ANALYSIS.md)** — mcp-scan (Snyk), Cisco skill-scanner, cc-audit, agent-audit. Матрица возможностей
- `[start]` **[MARKET_AND_SECURITY.md](../../research/MARKET_AND_SECURITY.md)** — 66K+ скилов, ClawHavoc, OWASP Agentic Top 10, EU AI Act
- **[USER_PAIN_POINTS.md](../../research/USER_PAIN_POINTS.md)** — 8 ключевых проблем: 95% FP, cloud-зависимость, нет auto-fix
- [CC_AUDIT_DEEP_ANALYSIS.md](../../research/CC_AUDIT_DEEP_ANALYSIS.md) — cc-audit: 55K LOC, 98 rules, 8 scanners, 7-layer arch

---

## Research — Early Research

Ранние итерации (Go CLI, skill-lint). Исторический контекст, актуальны только как справка:

- `[reference]` [rust-rule-engine-architecture.md](../../research/rust-rule-engine-architecture.md) — Rule engine архитектура (Rust)
- `[reference]` [rule-engine-architecture.md](../../research/rule-engine-architecture.md) — Rule engine архитектура (Go)
- `[reference]` [code-examples-and-benchmarks.md](../../research/code-examples-and-benchmarks.md) — MVP security linter (~800 LOC) + бенчмарки
- `[reference]` [code-examples.md](../../research/code-examples.md) — Примеры кода (Go)
- `[reference]` [benchmarks-performance.md](../../research/benchmarks-performance.md) — Бенчмарки производительности
- `[reference]` [implementation-roadmap.md](../../research/implementation-roadmap.md) — Roadmap (ранняя версия)
- `[reference]` [GO-LINTER-SUMMARY.md](../../research/GO-LINTER-SUMMARY.md) — Go CLI linter резюме
- `[reference]` [VALIDATION_AND_LINTING_ANALYSIS.md](../../research/VALIDATION_AND_LINTING_ANALYSIS.md) — Детальное исследование: валидация и линтинг
- `[reference]` [SKILL_LINT_QUICK_START.md](../../research/SKILL_LINT_QUICK_START.md) — skill-lint Quick Start
- `[reference]` [skill-lint-examples.md](../../research/skill-lint-examples.md) — Практические примеры skill-lint
- `[reference]` [skill-lint-diagrams.md](../../research/skill-lint-diagrams.md) — Диаграммы архитектуры skill-lint

---

## Research — Deep Dive (../../research/deep/)

54 файла глубоких исследований, сгруппированные по 7 темам.

### Architecture & Design (13 файлов)

- `[start]` **[adapter-architecture-design.md](../../research/deep/adapter-architecture-design.md)** — FORMAT vs DOMAIN split для адаптеров. Ключевое архитектурное решение
- `[start]` **[complex-rules-architecture.md](../../research/deep/complex-rules-architecture.md)** — declare_rule! macro, Enhanced YAML Layer 2.5, Rule trait
- `[start]` **[rust-workspace-patterns.md](../../research/deep/rust-workspace-patterns.md)** — 7 workspace анализов (Ruff, Biome, Tokio). Sweet spot: 12-15 crates
- **[workspace-versioning-strategy.md](../../research/deep/workspace-versioning-strategy.md)** — 3-4 public crates, api→1.0, axum-core+Ruff model
- **[crate-split-decision-framework.md](../../research/deep/crate-split-decision-framework.md)** — Когда split vs merge. suppress→engine, cache→engine
- **[architecture-weak-spots.md](../../research/deep/architecture-weak-spots.md)** — 37 рисков, 6 требуют изменений ДО начала кода
- [multi-format-parser-patterns.md](../../research/deep/multi-format-parser-patterns.md) — Biome/Semgrep/Hadolint patterns для парсинга
- [skill-formats-future.md](../../research/deep/skill-formats-future.md) — 95% скилов = Markdown. SkillModel = universal representation
- [rust-plugin-architectures.md](../../research/deep/rust-plugin-architectures.md) — Plugin архитектуры в Rust экосистеме
- [plugin-arch-validation.md](../../research/deep/plugin-arch-validation.md) — Валидация plugin архитектуры
- [plugin-validation-synthesis.md](../../research/deep/plugin-validation-synthesis.md) — Синтез валидации от 3 агентов
- [plugin-system-lessons.md](../../research/deep/plugin-system-lessons.md) — Уроки из ESLint, Webpack, Babel, Jenkins
- [plugin-ecosystem-failures.md](../../research/deep/plugin-ecosystem-failures.md) — Post-mortems: WordPress, Babel, Jenkins anti-patterns

### Parsers, Rules & Detection (8 файлов)

- `[start]` **[markdown-parsing-pitfalls.md](../../research/deep/markdown-parsing-pitfalls.md)** — 28 граблей MD парсинга. HTML comments = 10/10 attack surface. 25 уникальных правил
- `[start]` **[auto-fix-architecture.md](../../research/deep/auto-fix-architecture.md)** — Auto-fix = killer feature (ни один конкурент не имеет)
- [fixable-patterns-catalog.md](../../research/deep/fixable-patterns-catalog.md) — Каталог 250+ portable правил из OSS
- [false-positive-reduction.md](../../research/deep/false-positive-reduction.md) — Google Tricorder, 3-pass стратегии снижения FP
- [real-malware-samples.md](../../research/deep/real-malware-samples.md) — ClawHavoc 824, postmark-mcp, CVEs — реальные образцы
- [security-detection-libraries.md](../../research/deep/security-detection-libraries.md) — Nosey Parker, Gitleaks, GuardDog, Vigil
- [existing-malicious-detectors.md](../../research/deep/existing-malicious-detectors.md) — Обзор существующих детекторов
- [yara-x-verified-implementation.md](../../research/deep/yara-x-verified-implementation.md) — YARA-X v1.13: build.rs, serialize, wasmtime

### Performance, Config & Pitfalls (8 файлов)

- `[start]` **[config-design-failures.md](../../research/deep/config-design-failures.md)** — Unknown keys = error, кэш хэширования, explain-config CLI
- `[start]` **[linter-postmortems.md](../../research/deep/linter-postmortems.md)** — Post-mortems: Ruff 0.x, ESLint flat config, Clippy
- **[rust-cli-pitfalls.md](../../research/deep/rust-cli-pitfalls.md)** — SIGPIPE, CRLF, atty, UNC paths, exit codes
- **[sarif-ci-pitfalls.md](../../research/deep/sarif-ci-pitfalls.md)** — SARIF в CI/CD: 5K limit, 10MB, fingerprints
- [performance-pitfalls.md](../../research/deep/performance-pitfalls.md) — RegexSet, mimalloc +15-30%, rayon 3-5x
- [monorepo-versioning-pitfalls.md](../../research/deep/monorepo-versioning-pitfalls.md) — publish=false для internal, release-plz bugs
- [sarif-and-annotations.md](../../research/deep/sarif-and-annotations.md) — SARIF 2.1.0 спецификация, примеры
- [cicd-integration-patterns.md](../../research/deep/cicd-integration-patterns.md) — Semgrep/Trivy/CodeQL паттерны CI/CD

### Competitive Analysis (9 файлов)

- `[start]` **[honest-threat-assessment.md](../../research/deep/honest-threat-assessment.md)** — Честная оценка угроз и позиционирования
- **[snyk-agent-scan-deep-dive.md](../../research/deep/snyk-agent-scan-deep-dive.md)** — Snyk купил Invariant Labs. ~1,971★ (март 2026), Apache-2.0
- **[cisco-scanners-deep-dive.md](../../research/deep/cisco-scanners-deep-dive.md)** — Cisco: 3 сканера (mcp-scanner, skill-scanner, a2a-scanner)
- [cisco-scanners-analysis.md](../../research/deep/cisco-scanners-analysis.md) — Cisco 95% FP, YARA rules, Meta-Analyzer
- [new-competitors-deep-dive.md](../../research/deep/new-competitors-deep-dive.md) — MEDUSA, Agentic Radar, Ant Group MCPScan
- [missed-oss-competitors.md](../../research/deep/missed-oss-competitors.md) — Упущенные OSS конкуренты
- [niche-competitors-triple-agent-synthesis.md](../../research/deep/niche-competitors-triple-agent-synthesis.md) — Ниша lintai: синтез 3 агентов (skillscan-security, mcphound, CI/IDE слой, catch-up)
- [tencent-ai-infra-guard-deep-dive.md](../../research/deep/tencent-ai-infra-guard-deep-dive.md) — Tencent A.I.G: ~3,321★ (март 2026), Docker-only, LLM-dependent
- [enterprise-ai-security-landscape.md](../../research/deep/enterprise-ai-security-landscape.md) — Корпоративный ландшафт AI security
- [mcp-scan-deep-analysis.md](../../research/deep/mcp-scan-deep-analysis.md) — mcp-scan internals, 5 critical bugs

### Distribution & Ecosystem (5 файлов)

- `[start]` [cross-compilation-distribution.md](../../research/deep/cross-compilation-distribution.md) — Cross-compilation: armv7, aarch64, x86_64
- [npm-distribution-implementation.md](../../research/deep/npm-distribution-implementation.md) — npm distribution (Biome JS shim, maturin)
- [pre-install-scanning.md](../../research/deep/pre-install-scanning.md) — Pre-install scanning patterns
- [pre-install-ecosystem-patterns.md](../../research/deep/pre-install-ecosystem-patterns.md) — Socket.dev, cargo-vet, Sigstore
- [platform-skill-formats.md](../../research/deep/platform-skill-formats.md) — 14 платформ, форматы файлов

### Strategy & Business (4 файла)

- `[start]` [killer-features-roadmap.md](../../research/deep/killer-features-roadmap.md) — Roadmap killer features
- [monetization-models.md](../../research/deep/monetization-models.md) — 5 моделей монетизации, CLA vs DCO
- [fork-legal-analysis.md](../../research/deep/fork-legal-analysis.md) — Легальный анализ (MIT, Apache 2.0, patents)
- [ai-scanner-value-proposition.md](../../research/deep/ai-scanner-value-proposition.md) — Value proposition AI security scanner

### Linter Deep Dives (7 файлов)

- `[start]` **[ruff-deep-dive.md](../../research/deep/ruff-deep-dive.md)** — Ruff: 0.x 3+ года, архитектура, уроки
- `[start]` **[biome-semgrep-clippy-deep-dive.md](../../research/deep/biome-semgrep-clippy-deep-dive.md)** — Biome (94 crates), Semgrep, Clippy — архитектура и type system
- [eslint-deep-dive.md](../../research/deep/eslint-deep-dive.md) — ESLint: flat config, 7 лет миграции
- [linter-plugin-ecosystems.md](../../research/deep/linter-plugin-ecosystems.md) — 21 экосистема плагинов
- [cc-audit-engine-analysis.md](../../research/deep/cc-audit-engine-analysis.md) — cc-audit: 8 scanners, rule quality
- [offline-first-architecture.md](../../research/deep/offline-first-architecture.md) — Offline-first: ClamAV, 3-tier rules
- [cloud-vs-offline-analysis.md](../../research/deep/cloud-vs-offline-analysis.md) — Cloud vs Offline сравнение

---

## Research — Distribution (../../research/distribution/)

- `[start]` [DISTRIBUTION_SUMMARY.md](../../research/distribution/DISTRIBUTION_SUMMARY.md) — Сравнение стратегий: npm, PyPI, Homebrew, cargo-binstall
- [distribution-comparison-table.md](../../research/distribution/distribution-comparison-table.md) — Детальная таблица сравнения
- [npm-wrapper-guide.md](../../research/distribution/npm-wrapper-guide.md) — Как упаковать Rust CLI в npm (Biome shim)
- [goreleaser-configs-examples.md](../../research/distribution/goreleaser-configs-examples.md) — Примеры goreleaser конфигов
- [RUST_CLI_DISTRIBUTION_ANALYSIS.md](../../research/distribution/RUST_CLI_DISTRIBUTION_ANALYSIS.md) — Полный анализ распределения Rust CLI
- `[reference]` [go-cli-distribution-research.md](../../research/distribution/go-cli-distribution-research.md) — Go CLI distribution (ранний ресёрч)

---

## Research — Rust CLI (../../research/rust-cli/)

- `[start]` [RUST_CLI_SUMMARY.md](../../research/rust-cli/RUST_CLI_SUMMARY.md) — Краткое резюме Rust CLI
- [RUST_CLI_README.md](../../research/rust-cli/RUST_CLI_README.md) — Документация Rust CLI
- [RUST_CLI_QUICK_START.md](../../research/rust-cli/RUST_CLI_QUICK_START.md) — Быстрый старт
- [RUST_CLI_METRICS_SUMMARY.md](../../research/rust-cli/RUST_CLI_METRICS_SUMMARY.md) — Метрики производительности

---

## Research — Skill Lint (../../research/skill-lint/)

Ранние итерации skill-lint (до переименования в lintai):

- `[reference]` [SKILL_LINT_ARCHITECTURE.md](../../research/skill-lint/SKILL_LINT_ARCHITECTURE.md) — Детальная архитектура (61.9 KB)
- `[reference]` [SKILL_LINT_SUMMARY.md](../../research/skill-lint/SKILL_LINT_SUMMARY.md) — Краткое резюме

---

## Stats

| Метрика | Значение |
|---------|----------|
| Всего документов | 86+ |
| Research deep dive | 54 файла, ~49K строк |
| Research agents использовано | 19+ (несколько батчей) |
| Покрытие | Рынок, конкуренты, архитектура, rules engine, distribution, CI/CD, legal, monetization, 14 платформ, real malware, YARA-X, parser pitfalls |
| Код | Активный Rust workspace `lintai`; `v0.1` delivery cycle completed, current work is post-`v0.1` rule and remediation expansion |
