# lintai — Architecture Decisions (canonical)

> Статус: **зафиксировано** (последнее обновление: 2026-02-28)
> Цель: сохранить фундаментальные решения, которые дорого менять после 5K+ LOC.

## 0) Invariants (не меняем)

- **Offline-first + deterministic**: ядро не зависит от облачных LLM.
- **DIP/OCP через контракт**: `lintai-api` = стабильный контракт; `lintai-engine` = оркестратор; providers/formatters = реализации.
- **FORMAT vs DOMAIN split**: форматный парсинг в `lintai-parse-*`, доменная интерпретация в `lintai-adapter-*`, правила — только в `RuleProvider`.
- **Regions/zones-first**: контекст (offsets/regions) важнее lossless CST для снижения FP.

## 0.1) Codebase strategy (зафиксировано)

- **No fork**: кодовая база `lintai` пишется **с нуля** под нашу архитектуру.
- **Reuse by porting**: при необходимости **портируем** проверенные компоненты/правила/эвристики из OSS (включая `cc-audit`) с корректным attribution и соблюдением лицензий.

## 0.2) MVP v0.1 scope + targets (зафиксировано)

- **Must-scope v0.1**: `SKILL.md`, `CLAUDE.md`, `.mdc` / `.cursorrules`, `mcp.json`, **Cursor Plugins**.
- **Targets v0.1**: сборка/релиз сразу на всех целевых таргетах (включая Windows и Linux musl), без “добавим позже”.

## 0.3) Capabilities / Scope manifest (зафиксировано как feature)

Чтобы решать “intent vs behavior” детерминированно (без LLM-as-judge), вводим опциональную декларацию **capabilities/scope**:
- На уровне конкретного skill — через frontmatter в `SKILL.md`
- На уровне папки/проекта — через policy в `lintai.toml`
- Дополнительно:
  - **MCP tool schema annotations** (расширение `mcp.json`)
  - **Cursor plugin manifest extension** (`plugin.json`/`hooks.json`)

Док: `FEATURE_CAPABILITIES_MANIFEST.md`.

## 0.4) Правила: строгий quality bar и реалистичные объёмы (зафиксировано)

Мы делаем **строго надёжные** правила (низкий FP), без “хардкода текста” и без магии, с доказательствами и тестами.

Док: `RULE_QUALITY_POLICY.md`.

## 1) Plugin strategy (A сейчас, готовность к B)

- **Scope**: плагины расширяют **только rules** (RuleProvider).  
  Адаптеры/детекция/парсинг остаются встроенными (security-critical, влияет на FP и целостность пайплайна).
- **WASM timeline**: WASM host внедряем **после v0.2** (когда стабилизированы `ScanContext`/`Finding` и YAML engine).
- **WIT stability**: до **v1.0** plugin API = **experimental** (может ломаться); начиная с **v1.0** — **immutable** контракт.
- **Distribution**: remote packs/plugins — **Git URL + pin (tag/commit) + SHA256**, плюс local path.
- **Trust model**: по умолчанию **SHA256 pin required**; unpinned — только по явному разрешению в конфиге.

## 2) WASM sandbox (v1 host capabilities)

- **Host API v1 (минимум)**: `read_file` (text), `get_regions/zones`, `get_config`, `log`.
- **Запреты**: no network, no filesystem write.
- **Лимиты по умолчанию**: 64MB RAM, 2s CPU-time (timeout), ограничения на размер/кол-во файлов.

## 3) Suppress model (security-first)

- Для Markdown/MDC/инструкций suppress **внешний**: `.lintai/suppress.toml` (не в канале, который читает агент).
- Inline suppress допустим для code-файлов (yaml/json/toml/sh/dockerfile), но всегда с **rule id + reason**.

## 4) YAML safety

- `serde_yaml` **не используем** (устаревание + отсутствие защит по умолчанию).
- Базовая замена: **`serde_yaml_bw`** (drop-in, с защитами).  
  Для frontmatter обязательны лимиты глубины/размера и fail-closed поведение.

## 5) `RegionKind` / `TextRegion` (FP reduction)

- MVP enum минимальный:
  - Normal
  - Heading
  - CodeBlock
  - Frontmatter
  - Blockquote
  - HtmlComment
- Расширение только через `#[non_exhaustive]` + новые значения, без breaking.

## 6) File type detection

- `FileTypeDetector` живёт в engine (router).
- Адаптеры регистрируют detection rules (filename/path/ext + optional content probe).
- Пользователь может override детекцию через `lintai.toml` (для edge cases вроде `SKILL.md` как docs).

## 7) `RuleProvider` contract

- `RuleProvider` is a result-only rule authoring contract.
- Engine executes providers through explicit backends, not direct raw provider injection.
- Backend execution mode carries `ScanScope::{PerFile, Workspace}`; the old `requires_full_scan()` path is not part of the contract anymore.
- Product path executes shipped built-in providers behind an isolated subprocess boundary for truthful hard timeouts.

## 8) Workspace (MVP → later)

MVP стартует с **6–7 крейтов**:

- **`lintai-api` (public)**: stable contract (types + traits + макросы).
- **`lintai-testing` (internal in v0.1)**: support harness while it still depends on engine internals.
- **`lintai-engine` (internal)**: оркестратор/pipeline (suppress/cache как модули).
- **`lintai-parse` (internal)**: format-facing parsing (`markdown/json/shell/frontmatter`).
- **`lintai-adapters` (internal)**: artifact-kind routing and domain semantics over parsed format output.
- **`lintai-ai-security` (internal)**: native rules provider.
- **`lintai-fix` (internal)**: применение Fix’ов к файлам (CLI/LSP consumer).
- **`lintai-cli` (binary)**: composition root + output (text/json/sarif как модули).

Позже (после MVP / v0.2+):

- **`lintai-yaml-engine`** (Layer 2 + 2.5 Enhanced YAML)
- **`lintai-wasm-host` + `lintai-wasm-sdk`**
- **`lintai-lsp`**, **`lintai-yara`**, registry/adapters extra

## 9) `lintai-api`: контракт (что именно стабилизируем)

### Data model

- **`ParsedDocument`/parsed output = data, не trait**: расширяем через новые поля (`#[non_exhaustive]` где уместно), не через разрастание trait surface.
- **Regions/zones**: минимальный универсальный список регионов с byte-span и контекстом.

### `Finding` (canonical)

- `Finding` SARIF-friendly и расширяемый.
- Обязательно иметь:
  - **`Location`**: **и byte-span, и line/col** (line/col может быть derived/optional; source of truth = span).
  - **`evidence: Vec<Evidence>`** как typed structured proof carrier.
  - **`fix: Option<Fix>`** + applicability (`Safe`/`Unsafe`/`Suggestion`).
  - **`metadata: Option<serde_json::Value>`** как escape hatch (аналог SARIF properties bag).
  - **`stable_key`** (компоненты для дедупликации): хранится в finding; SARIF/CI fingerprint вычисляется на выходе.

### Finding fingerprint / dedup (зафиксировано)

- В `Finding` храним **`stable_key`** (например: rule_code + file + span + optional “logical sub-id”).
- **Fingerprint** (SARIF/CI) вычисляется **только на выходе** из `stable_key` и других стабильных полей.

### Rule codes: **prefix ≠ category**

- **`RuleCode` = стабильный идентификатор/namespace**, а не “категория”.
- **`Category`** — отдельное поле в `RuleMetadata`, может меняться без переименования кода.

## 10) Правила: слои (без усложнений на старте)

- **Layer 1 (Native Rust)**: основной quality bar, сложные эвристики/корреляции.
- **Layer 2 (YAML regex)**: быстрые data-driven паттерны.
- **Layer 2.5 (Enhanced YAML)**: структурный матчинг по ParsedDocument (sections/regions/captures).
- **Layer 3 (WASM)**: позже, для community/сложных правил с sandbox.

Оценка реалистична: YAML покрывает ~50–60%, остальное — native/Enhanced YAML/WASM.

### Authoring native rules: `declare_rule!` (macro_rules)

- **Без proc-macro на MVP**: используем `declare_rule!` (macro_rules) для метадаты + `impl Rule`.
- Причина: compile time и dependency surface (syn/quote/proc-macro2) не окупаются на старте.

## 11) `RuleProvider` trait: result-only rule authoring contract

`RuleProvider` фиксируется как rule-authoring contract:

- `check_result()` обязателен
- `check_workspace_result()` остаётся default-empty для non-workspace providers
- remediation lives on `Finding.fix` / `Suggestion.fix`, not on a provider fix hook

Engine execution model вынесен отдельно в backend layer; lifecycle hooks больше не используются.
Execution policy belongs to `ProviderBackend`, not to `RuleProvider`, including timeout and scan scope.

### Timeout model (current)

- **Shipped built-in providers** use isolated execution in product/runtime composition and can be terminated on timeout.
- **In-process execution** remains available only through an explicit backend wrapper, not as hidden raw provider injection.

### Native rules registration (зафиксировано)

- В native provider’е правила регистрируются через **явный список/массив** (без `inventory`-магии).

## 12) Markdown suppress: primary = external file

Inline suppress внутри Markdown **виден агентам** и является attack vector.

- **Primary**: `.lintai/suppress.toml` (или `.lintai/suppress.json`).
- Inline suppress в Markdown **по умолчанию запрещён**. Если потребуется совместимость — только через явный флаг/настройку и с предупреждением, что это insecure.

Для non-Markdown inline suppress остаётся нормальным (YAML/TOML/JSON/shell).

## 13) File routing: `FileTypeDetector` обязателен с MVP

- Детекция типа файла = отдельная ответственность (filename/path/ext + optional content probe).
- Роутинг НЕ прячем внутри парсеров.

## 14) YAML безопасность: `serde_yaml_bw`

- `serde_yaml` deprecated; для YAML используем **`serde_yaml_bw`**.
- Frontmatter/rules parsing всегда с лимитами (size/anchors/depth/timeouts) и строгой валидацией.

## 15) Capabilities policy precedence (зафиксировано)

- Если заданы **и** project policy (`lintai.toml`), **и** per-skill frontmatter (`SKILL.md`), применяется precedence:
  1) project policy — источник истины
  2) frontmatter — уточнение в рамках политики
- Конфликт frontmatter vs policy: по умолчанию **warning**, по настройке — **deny**.

## 16) Cache invalidation (зафиксировано)

Кэш хэшируется по:
- `content_hash`
- `config_hash`
- `ruleset_version` / `provider_versions`
- `engine_version`

## 17) CLI contract (зафиксировано)

### Exit codes

- `scan`: `0` — blocking findings нет, `1` — есть хотя бы один effective severity = deny finding
- `fix`: `0` — preview/apply завершён успешно, `1` — один или несколько выбранных safe fixes были пропущены безопасно
- `2` — ошибка выполнения (невалидный конфиг, I/O, internal error)

### Current remediation contract

- `lintai fix` — публичная CLI surface.
- **Safe autofix** в текущем контракте ограничен `SEC101` и `SEC103`.
- Для более широкого набора stable rules поддерживаются **message suggestions**.
- Для узкого allowlist'а stable rules поддерживаются **preview-only candidate patch suggestions**.
- Preview-only remediations не применяются автоматически через `fix --apply`.

### Cross-platform output behavior

- **SIGPIPE**: не паниковать при пайпинге вывода (например `| head`).
- **TTY detection**: использовать `std::io::IsTerminal` (не `atty`).
- **Цвета**: уважать `NO_COLOR`, `TERM=dumb`, и уметь форсировать цвет по флагу.
- **Windows ANSI**: включать ANSI escape codes через `enable_ansi_support` (no-op на Unix).
- **CRLF**: при чтении файлов нормализовать `\r\n` → `\n` для парсинга/оффсетов.

## 18) File discovery (зафиксировано)

- Для обхода файлов использовать **`ignore` crate** (parallel + `.gitignore` semantics).
- **Symlinks**: по умолчанию **не следовать** по symlink (защита от infinite loops); опционально включать follow через настройку.
- Default excludes: `.git/`, `node_modules/`, `target/`, `dist/`, `build/`, `__pycache__/`, `vendor/` (и прочие “массовые” директории).

## 19) Config strictness & schema (зафиксировано)

- **Unknown keys = error** (строгая валидация конфига, fail-closed).
- Команда **`lintai explain-config <file>`** обязательна для дебага effective config.
- Публиковать **JSON Schema** для `lintai.toml` и регистрировать в SchemaStore (Taplo autocomplete).

## 20) stable_key (зафиксировано)

Для дедупликации результатов фиксируем “stable_key” как источник истины, а fingerprint считаем на выходе.

Рекомендуемый состав `stable_key` (MVP):
- `rule_code`
- `artifact_path` (нормализованный путь, предпочтительно relative к project root)
- `span.start_byte`, `span.end_byte`
- `subject_id` (опционально, если правило находит несколько сущностей в одном span: например имя tool/command)

Принцип: **stable_key не зависит от текста сообщения**, чтобы правки wording не ломали дедуп в CI/SARIF.

## 21) Config merge semantics (зафиксировано)

- Конфиг `lintai.toml` имеет **простые и предсказуемые** правила слияния.
- Принцип: **явный override вместо “умного merge”**.
  - Per-file `[[overrides]]` **перекрывает** значения базовой конфигурации для совпавших файлов.
  - Списки (arrays) по умолчанию: **replace**, не “склеивать”.
  - Никаких неявных “union/merge” режимов без явного ключа/флага.

Цель: избежать путаницы, как в ESLint/Ruff миграциях.

## 22) Normalization (зафиксировано)

Чтобы результаты были воспроизводимыми и не “дрожали” между ОС/CI:

- **Newlines**: при чтении текстов нормализуем `\r\n` → `\n` (для парсинга/offsets).
- **Paths**:
  - В `stable_key` и JSON-выводе используем **нормализованный путь относительно project root** (если root определён).
  - Путь в выводе — **в одном стиле**, без зависимости от ОС (предпочтительно forward slashes в machine output).
- **Terminal UX**: выравнивание — best effort; для machine output никаких таблиц/ANSI.

## 23) Machine-readable JSON contract (зафиксировано)

- JSON output — это **публичный контракт** для CI/интеграций.
- Принципы:
  - envelope version фиксируется как **`schema_version`**
  - Поля добавляем backward-compatible (новые поля optional, старые не ломаем).
  - `stable_key` — источник дедупликации в JSON.
  - Для нестандартных данных используем `metadata` (escape hatch), а не “ломаем схему”.

## 24) Glossary / терминология (зафиксировано)

- Все ключевые термины фиксируем в `GLOSSARY.md`.
- Правило: не вводим новые синонимы/названия сущностей без обновления glossary.
