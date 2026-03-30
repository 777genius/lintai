# Топ правил для AI-линтера (security-first)

Документ **ручной**: приоритизация и threat-model для репозиториев со **skills**, **MCP**, **инструкциями в Markdown**, **tool JSON**, **плагинами IDE** и **CI-артефактами**. Не заменяет сгенерированный каталог текущих кодов правил — см. **[SECURITY_RULES.md](SECURITY_RULES.md)**.

**Срез:** 29 марта 2026. Часть правил уже покрывается shipped `SEC*` в `lintai-ai-security`, часть — кандидаты на следующие итерации.

## Актуализация для skills markdown (2026-03-29)

Смотрите обновлённую секцию ниже: **## Актуализация (2026-03-29): top-6 правил для `skills markdown` (самые полезные)**.

## Синтез 15 исследовательских агентов (март 2026)

Был запущен **параллельный ресёрч** (15 подзадач) по направлениям: OWASP LLM Top 10 → статические аналоги; MITRE ATLAS mitigations → проверки в репо; официальный **MCP security** (в т.ч. spec 2025-11-25); **Cursor / VS Code / Claude Code** формы конфигов; **Agent Skills** spec; **ENISA ETL 2025**; **NIST AI 600-1**; **GitHub Copilot** custom instructions; **hooks / tasks / pre-commit**; **небезопасная сериализация весов** (HF/PyTorch guidance); **CVE** на MCP и AI-IDE; **JSON Schema** Tool (MCP); **RAG chunk** инварианты; **plugin.json** Cursor/Anthropic; **SBOM / ML-BOM**.

**Критерий отбора «лучших» для таблиц ниже:** детерминированная проверка по файлам, **security-релевантность**, переносимость между проектами, минимум ложных срабатываний при узкой формулировке. Отброшено: чистая эвристика «prompt injection» в prose; правила без первичного обоснования в спеке/доке.

**Про два кураторских списка (волна 1 / волна 2):** нумерация отражает приоритет **внутри** прохода куратора; **между** списками **нет единого глобального ранга** (волна 2 — CI, контейнеры, менеджеры пакетов: часто тот же класс blast radius, что пункты волны 1). Пересечения по смыслу намеренные (MCP, hooks, supply chain, ML — разные носители).

**Кураторский топ-12 (лучшее из волны):**

1. **MCP Tool по schema:** обязательные **`name`** + **`inputSchema`** (`$defs.Tool` в официальном `schema.json`).  
2. **Strict function tools (OpenAI/Anthropic):** `additionalProperties: false` + полнота `required` при `strict: true`.  
3. **Литералы опасных хостов/IP** в OAuth/MCP URL в репо (`169.254.169.254`, внутренние диапазоны) — см. раздел SSRF в MCP security.  
4. **Отключение TLS** в коде/конфигах рядом с OAuth (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, …).  
5. **GitHub Copilot instructions:** суффикс **`.instructions.md`**, обязательный **`applyTo`** для path-specific, лимит **4000 символов** для **code review** (по докам GitHub).  
6. **Плагины:** относительные пути без **`..`**, запрет **`hooks` / `mcpServers` / `permissionMode`** во frontmatter агентов внутри Claude plugin (по докам Anthropic).  
7. **Hooks / automation:** `curl|bash`, **`runOn: folderOpen`** + произвольная shell-команда; **закреплённый `rev`** в `.pre-commit-config.yaml`.  
8. **ML артефакты в git:** политика против **`.pkl`** и небезопасных бинарных весов; приоритет **Safetensors**; минимальная версия PyTorch при `weights_only` (GHSA-53q9-r3pm-6pq6).  
9. **SBOM:** `cyclonedx validate` + элементы **NTIA minimum** для репо с моделями (**ML-BOM** narrative).  
10. **OWASP LLM03/04/06** как статика: lockfile, манифест датасета с хэшами, непустой allowlist tools (политика репо).  
11. **MITRE AML.M0033 / M0028:** схема tool specs + least-privilege в закоммиченных конфигах агента.  
12. **CVE semver:** дополнение **Cursor** / **VS Code+Copilot** где продукт фиксируется в репо (см. таблицу ниже).

### Вторая волна: ещё 15 агентов (март 2026)

Темы: **devcontainers / Docker `devcontainer.metadata`**, **YAML** (`!!python/*`, merge/anchors, ключ `on` в GHA), **SSTI-аналог** (Jinja/Handlebars + промпты), **npm/pnpm/Corepack/install scripts / overrides drift**, **Python** (`extra-index-url`, VCS без SHA, `setup.py`), **DVC / MLflow / W&B / HF** endpoint в git, **OTEL / LangSmith / Langfuse** секреты и «голые» промпты в трейсах, **GHA** (инъекция в `run:`, pin SHA, token+недоверенный код, cache poisoning), **`.env.example` / direnv**, **Unicode tool id / ReDoS** в regex-полях конфигов, **WASI / Extism manifest**, **Cursor** (`.cursorignore` vs terminal/MCP, `envFile`), **Claude Code** (`settings.json`, hooks, `bypassPermissions`), **vector DB** compose/Helm.

**Кураторский топ новых правил (из второй волны):**

1. **`initializeCommand` devcontainer** выполняется на **хосте**; **Features** из произвольного OCI-реестра; **bind-mount** `~/.ssh`, cloud CLI, **`docker.sock`**.  
2. **Lifecycle** в **`LABEL devcontainer.metadata`** в образе — скрытый от ревью `devcontainer.json` вектор.  
3. **GHA:** выражения **`$\{\{ inputs.* \}\}` / event** прямо в **`run:`** → script injection; **third-party `uses:`** не на **полный SHA**; сочетание **`contents: write`** с checkout **кода из форка**; **cache** общий между недоверенным и привилегированным job.  
4. **YAML:** теги **`!!python/object*`** в workflow/compose; **anchors + `<<`** рядом с **`permissions` / `environment`**.  
5. **Lockfile `hasInstallScript`** без политики allowlist; **`dangerouslyAllowAllBuilds`** (pnpm); **`packageManager`** без **integrity hash** (Corepack).  
6. **`--extra-index-url` / `PIP_EXTRA_INDEX_URL`** на неутверждённый хост (dependency confusion); **git+ без pin коммита**; **`exec`/`eval` в `setup.py`**.  
7. **Committed URL** DVC remote / **`MLFLOW_TRACKING_URI`** / **`WANDB_BASE_URL`** / **`HF_ENDPOINT`**: **http** или **private/metadata** хосты.  
8. **Экспорт телеметрии:** литералы **API key** в YAML коллектора; **LangSmith** `HIDE_INPUTS=false` в prod-шаблонах при включённом tracing.  
9. **SSTI-слой:** **`Environment.from_string` / `Template(`** с f-string/конкатенацией из ненадёжных данных; **delimiters шаблонов** в закоммиченных промптах без политики **variables-only / `\{% raw %\}`**.  
10. **Tool / `operationId`:** **ASCII-only** machine id; запрет **default-ignorable** / ZWSP в идентификаторах (UTS #39).  
11. **ReDoS:** эвристики на значениях ключей **`pattern` / `regex` / `regexp`** (вложенные квантификаторы, `(a|aa)+`).  
12. **Extism:** **`allowed_hosts: null`** = произвольный исходящий HTTP; узкие **`allowed_paths`**.  
13. **Cursor:** официально **terminal и MCP не уважают `.cursorignore`** — секреты не полагаться только на ignore; литералы в **`env`/`headers`/`auth`** и **`envFile`** в `.cursor/mcp.json`.  
14. **Claude Code (committed):** **`permissions.defaultMode: bypassPermissions`**, HTTP-hook **не https** / вне **`allowedHttpHookUrls`**, **hook `command`** с absolute path без **`$CLAUDE_PROJECT_DIR`**.  
15. **Vector stack:** **`http://`** к облачному вендору; **api_key** литералом в Helm/values; **compose `ports`** `0.0.0.0` для qdrant/weaviate/chroma без политики.

---

## Актуализация (2026-03-29): top-6 правил для `skills markdown` (самые полезные)

Ниже — 6 правил с максимальной практической ценностью для `SKILL.md`, `AGENTS.md`, `.mdc`, `.github/instructions`, `.github/copilot-instructions.md`, `.cursor` и MCP-конфигов.

### Топ-6 правил (приоритет сообщества)

| Ранг | Правило | Почему полезно | Уверенность | Надёжность |
|---|---|---|---:|---:|
| 1 | `SEC-COPILOT-PATH-LAYOUT` | Формат и расположение инструкций (`.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `applyTo`), чтобы `instructions` реально применялись в нужном контексте. | 10/10 | 10/10 |
| 2 | `SEC-COPILOT-4K` | В code-review лимит `4000` символов (контроль по GitHub docs) — исключает тихое отбрасывание хвостовой логики инструкций. | 10/10 | 10/10 |
| 3 | `SEC-OWASP-TOOLS` | Принудительный allowlist инструментов (без `tools: ["*"]`) снижает excessive agency и blast radius. | 10/10 | 10/10 |
| 4 | `SEC-MCP-TOOL-REQ` | Наличие обязательных `name` и `inputSchema` в инструментах MCP/agent-интерфейсов предотвращает невалидный execution surface. | 10/10 | 10/10 |
| 5 | `SEC-OPENAI-STRICT` + `SEC-OPENAI-STRICT-REQ` + `SEC-ANTHROPIC-STRICT` | Строгая валидация аргументов tool-call блокирует неожиданную семантику и подмену параметров. | 10/10 | 9/10 |
| 6 | `SEC-MCP-LAUNCH` + `SEC-CURSOR-MCP-ENVFILE` + `SEC-CURSOR-IGNORE-NOT-BOUNDARY` | Реальный blast-radius контроль: запуск MCP без shell-пайпов + запрет утечки секретов через env/headers + не считаем `.cursorignore` security boundary. | 10/10 | 9/10 |

### Уже зашипленные quality-first правила из этого трека

- `SEC352` — AI-native markdown frontmatter grants unscoped Bash tool access
  - статус: `Preview`
  - community usefulness сейчас: `7/10`
  - надёжность: `9/10`
  - почему важно: ловит слишком широкий shell grant в AI instruction frontmatter без расплывчатой prose-эвристики
- `SEC353` — GitHub Copilot instruction markdown exceeds the 4000-character guidance limit
  - статус: `Preview`
  - community usefulness сейчас: `8/10`
  - надёжность: `9.5/10`
  - почему важно: привязан к официальному GitHub guidance и ловит structure-level проблему, из-за которой хвост инструкций может перестать реально работать
- `SEC354` — Path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9.5/10`
  - почему важно: ловит очень понятный structural misconfiguration, из-за которого path-specific Copilot instructions могут просто не применяться как задумано
- `SEC355` — AI-native markdown frontmatter grants wildcard tool access
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9.5/10`
  - почему важно: very direct least-privilege rule для skills и shared instructions; wildcard `*` слишком расширяет agency и плохо переживает community review
- `SEC356` — Plugin agent frontmatter sets `permissionMode`
  - статус: `Preview`
  - community usefulness сейчас: `8/10`
  - надёжность: `9.5/10`
  - почему важно: структурно запрещает смешивать permission policy с plugin agent content; это narrow spec-aligned signal, который легко объяснить сообществу
- `SEC357` — Plugin agent frontmatter sets `hooks`
  - статус: `Preview`
  - community usefulness сейчас: `7.5/10`
  - надёжность: `9.5/10`
  - почему важно: не даёт прятать hook execution policy внутрь agent content; остаётся узким и spec-aligned
- `SEC358` — Plugin agent frontmatter sets `mcpServers`
  - статус: `Preview`
  - community usefulness сейчас: `7.5/10`
  - надёжность: `9.5/10`
  - почему важно: отделяет plugin agent docs от client/server wiring; сообществу проще ревьюить такие boundary violations, чем широкие prose rules
- `SEC359` — Cursor rule frontmatter `alwaysApply` must be boolean
  - статус: `Preview`
  - community usefulness сейчас: `8/10`
  - надёжность: `9.5/10`
  - почему важно: ловит очень понятный contract bug в `.mdc` / `.cursorrules`, из-за которого Cursor rules могут применяться не так, как автор ожидал
- `SEC360` — Cursor rule frontmatter `globs` must be a sequence of patterns
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9.5/10`
  - почему важно: ловит path-targeting bug в `.mdc` / `.cursorrules`, из-за которого Cursor rule может тихо применяться не к тем файлам или не матчиться как задумано
- `SEC361` — Claude settings file is missing a top-level `$schema` reference
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9.5/10`
  - почему важно: даёт понятный quality contract для shared `.claude/settings.json`, улучшает editor validation и делает командные Claude settings проще для ревью и поддержки
- `SEC362` — Claude settings permissions allow `Bash(*)` in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `9/10`
  - надёжность: `9/10`
  - почему важно: ловит прямой overly-broad shell grant в shared Claude settings; для AI infra это более practically actionable signal, чем broad prose guidance
- `SEC363` — Claude settings hook command uses a home-directory path in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: ловит не-portable shared Claude hook wiring; для AI команд это понятный config smell, который легко чинится переходом на `$CLAUDE_PROJECT_DIR`
- `SEC364` — Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: это очень явный over-agency smell в shared Claude policy; сообществу легко объяснить, почему committed bypass default хуже, чем явные reviewed allowlists
- `SEC365` — Claude settings allow non-HTTPS `allowedHttpHookUrls` in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: это прямой transport-policy smell для shared Claude hook allowlist; `https://` проще защищать и публично отстаивать как командный стандарт
- `SEC366` — Claude settings allow dangerous host literals in `allowedHttpHookUrls`
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: metadata/private-network hook hosts в shared config выглядят как очень понятный SSRF/exfil policy smell и хорошо объясняются сообществу
- `SEC367` — Claude settings permissions allow `WebFetch(*)` in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: даёт очень понятный least-privilege signal для shared Claude network access; wildcard fetch grant легче всего оспорить в code review и легко сузить до reviewed endpoints
- `SEC368` — Claude settings hook command uses a repo-external absolute path in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9/10`
  - почему важно: ловит team-facing Claude hook wiring, которое жёстко привязано к внешнему filesystem path; community-friendly remediation очевиден — перейти на `$CLAUDE_PROJECT_DIR`
- `SEC369` — Claude settings permissions allow `Write(*)` in a shared committed config
  - статус: `Preview`
  - community usefulness сейчас: `9/10`
  - надёжность: `9/10`
  - почему важно: wildcard write grant в shared AI config сообществу объяснять проще всего; это очень явный least-privilege smell с очевидным remediation path
- `SEC370` — path-specific GitHub Copilot instruction markdown under `.github/instructions/` uses the wrong file suffix
  - статус: `Preview`
  - community usefulness сейчас: `8.5/10`
  - надёжность: `9.5/10`
  - почему важно: это очень понятный structural rule для AI tooling layout; если path-specific Copilot file не заканчивается на `.instructions.md`, repo получает тихий config drift, который сложно заметить в review
- `SEC371` — path-specific GitHub Copilot instruction markdown has an invalid `applyTo` shape
  - статус: `Preview`
  - community usefulness сейчас: `8/10`
  - надёжность: `9.5/10`
  - почему важно: rule хорошо объясняется сообществу как config-contract check; `applyTo` должен быть реально применимым target selector, а не пустым или malformed значением

### Минимальный релизный набор (1-й проход)

1. `SEC-COPILOT-PATH-LAYOUT`
2. `SEC-COPILOT-4K`
3. `SEC-OWASP-TOOLS`
4. `SEC-MCP-TOOL-REQ`
5. `SEC-OPENAI-STRICT` + `SEC-OPENAI-STRICT-REQ`

### Где линтовать для сообщества (top-3 по практичности, с оценками)

- **Вариант A: GitHub Action required check**  
  Уверенность: `10/10`  
  Надёжность: `10/10`  
  Почему: максимальный охват, enforce для каждого PR, единообразие для OSS-репозиториев.
- **Вариант B: pre-commit + локальный линт**  
  Уверенность: `9/10`  
  Надёжность: `8/10`  
  Почему: дешёвый вход, раннее обнаружение и меньше итераций PR.
- **Вариант C: PR advisory bot**  
  Уверенность: `8/10`  
  Надёжность: `7/10`  
  Почему: второй слой в проектах с legacy-репозиториями или без strict CI.

### Рекомендуемый rollout
`pre-commit` → обязательный GitHub Action → advisory-бот (поэтапно, без перегруза команд).

### Обновлённые источники 2025-2026 (критичные для этого блока)

- [GitHub Copilot customization / custom instructions](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions)  
- [GitHub Copilot customization cheat sheet](https://docs.github.com/en/enterprise-cloud%40latest/copilot/reference/customization-cheat-sheet)  
- [GitHub custom agents configuration](https://docs.github.com/en/copilot/reference/custom-agents-configuration), [response customization](https://docs.github.com/en/copilot/concepts/prompting/response-customization)
- [GitHub Actions security (script injections, pwn requests)](https://docs.github.com/en/actions/concepts/security/script-injections), [GitHub Security Lab](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)  
- [MCP spec/security + 2025-11-25 schema](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)  
- [OpenAI strict function/tool calling](https://platform.openai.com/docs/guides/function-calling)  
- [Anthropic Claude security/permissions/MCP/plugins/hooks](https://code.claude.com/docs/en/security), [settings](https://code.claude.com/docs/en/settings), [plugins reference](https://code.claude.com/docs/en/plugins-reference), [hooks](https://code.claude.com/docs/en/hooks)  
- [Cursor MCP / ignore limitations](https://docs.cursor.com/context/mcp), [ignore file](https://cursor.com/docs/reference/ignore-file)  
- [OWASP agentic LLM Top 10 (2025/2026)](https://genai.owasp.org/resource/2025-12-09/owasp-top-10-for-agentic-applications-for-2026)

## Принципы

1. **Security важнее совместимости:** gate CI в первую очередь на угрозы (утечки, подмена инструментов, supply chain, обход контракта аргументов, SSRF-литералы, автозапуск shell).
2. **Высокая точность:** схема, semver/CVE, байты/Unicode, URL-схема, структура JSON, числовые инварианты RAG **только при явных ключах** в файле.
3. **Широкая аудитория:** OSS skills, корпоративные MCP, monorepo с агентами и Copilot instructions.

---

## Тир S — security (рекомендуемый CI gate)

**Порядок строк в таблице:** не глобальный **рейтинг по CVSS**, а **кластеры по поверхности** (CVE → MCP/remote → контракт tool JSON / схема → markdown агента → снова MCP launch/vars → lockfile → локальные hooks → Copilot → supply chain: devcontainer / GHA / npm / Python → ML / observability / vector / WASM). Внутри кластера — от более узнаваемых к менее специфичным для AI-репо. Для ощущения «что важнее прямо сейчас» ориентируйтесь на **кураторские списки** и блок **«Минимальные наборы»**, а не на номер строки в Tier S.

| ID | Правило | Что проверяем | Угроза | Типичные пути |
|----|---------|----------------|--------|----------------|
| **SEC-MCP-CVE** | Версии **`mcp-remote`**, **`@modelcontextprotocol/sdk`** вне известных уязвимых диапазонов | RCE / cross-client data leak | `package.json`, lockfiles |
| **SEC-PRODUCT-CVE** | Версии **Cursor** / **Cursor CLI** / **VS Code** в репо или lock скане — см. таблицу CVE | Компрометация IDE/CLI | политика орг., скан установок |
| **SEC-MCP-URL** | Remote MCP: **`https`**, политика по loopback / private literal | SSRF, MITM, подмена OAuth flow | `mcp.json`, `.cursor/mcp.json`, `server.json` |
| **SEC-MCP-SSRF-LITERAL** | Литералы **`169.254.169.254`**, `metadata.google.internal`, частные диапазоны в строках OAuth/MCP | SSRF / metadata abuse | JSON, `.env.example`, код клиента MCP |
| **SEC-MCP-TLS-BYPASS** | Паттерны отключения проверки TLS рядом с HTTP-клиентами OAuth | MITM, утечка токенов | исходники, shell env в конфигах |
| **SEC-MCP-SECRETS** | Литералы секретов в **`env` / `headers`** MCP без индирекции (`${input:}`, `${env:}`) | Утечка в git | JSON конфигов MCP |
| **SEC-MCP-SHADOW** | **Дубликаты имён** MCP tools в дескрипторах репозитория | Tool shadowing | JSON дескрипторы |
| **SEC-MCP-TOOL-REQ** | По **MCP schema**: у `Tool` есть **`name`** и **`inputSchema`** (machine schema) | Невалидный tool → странное поведение агента | codegen, фикстуры |
| **SEC-TOOLS-COLLISION** | **Дубликаты `function.name`** в OpenAI-style tools | Подмена вызова | `**/tools*.json` |
| **SEC-OPENAI-STRICT** | При **`strict: true`**: рекурсивно **`additionalProperties: false`** в `parameters` | Обход контракта аргументов | tool JSON |
| **SEC-OPENAI-STRICT-REQ** | При **`strict: true`**: **`required`** покрывает все `properties` | То же | tool JSON |
| **SEC-ANTHROPIC-STRICT** | Anthropic **`strict` + `input_schema.additionalProperties: false`** | То же | Anthropic JSON |
| **SEC-JSONSCHEMA-META** | Валидация вложенной схемы по **JSON Schema 2020-12** meta-schema | Подмена/битая схема | `*schema*.json` |
| **SEC-MD-BIDI-ZWSP** | **Bidi control**, **ZWSP**, **BOM** в контексте агента | Trojan Source класс, скрытый текст | `SKILL.md`, `AGENTS.md`, `.cursor/rules/**/*`, Copilot instructions |
| **SEC-MD-DANGEROUS-URL** | Схемы **`javascript:`**, **`data:`**, **`vbscript:`** | Фишинг / рендер | `*.md`, `*.mdc` |
| **SEC-MD-PEM** | **PEM / private key** в markdown | Утечка ключей | те же |
| **SEC-MD-PIPE-SHELL** | Узкий **pipe-to-shell** в **fenced** блоках | RCE через инструкции | те же |
| **SEC-MCP-REMOTE-VARS** | `{var}` в remote URL ↔ ключи **`variables`** в `server.json` | Misconfig endpoint | `server.json` |
| **SEC-MCP-LAUNCH** | Цепочки **`&&` / `;` / `|`**, **`bash -c` / `sh -c`** в команде запуска MCP (высокосигнальные) | Local compromise через конфиг | JSON MCP, скрипты |
| **SEC-LOCKFILE** | Политика **lockfile** + **lockfile-lint** (https, allowed hosts) | Supply chain | npm/pnpm/yarn locks |
| **SEC-HOOK-AUTOEXEC** | **`curl\|wget … \| sh`**, **`runOn: folderOpen`** + не allowlist-команда | Supply chain / открытие папки = RCE | `.vscode/tasks.json`, hooks |
| **SEC-PRECOMMIT-PIN** | **`.pre-commit-config.yaml`**: `rev` не ветка/плавающий тег (политика SHA) | Подмена хука | `.pre-commit-config.yaml` |
| **SEC-ML-ARTIFACT** | Запрет **`.pkl`** и небезопасных бинарных весов в git (политика орг.) | RCE при загрузке весов | `**/*.pkl`, артефакты моделей |
| **SEC-COPILOT-FM** | Path-specific: суффикс **`.instructions.md`**, наличие **`applyTo`** во frontmatter | Неверная загрузка инструкций | `.github/instructions/**` |
| **SEC-COPILOT-4K** | Для веток с **Copilot code review**: длина файла инструкции ≤ **4000 символов** (по докам) | Тихий игнор хвоста при review | `.github/**/*.md` (политика) |
| **SEC-DEVCONTAINER-INIT-HOST** | Непустой **`initializeCommand`** в `devcontainer.json` | Произвольная команда на **хосте** до контейнера | `.devcontainer.json`, `.devcontainer/devcontainer.json` |
| **SEC-DEVCONTAINER-FEATURE-REGISTRY** | **`features`** с образами **вне org-allowlist** (произвольный OCI registry/namespace) | Supply-chain / RCE при сборке feature | те же |
| **SEC-DEVCONTAINER-BIND-SENSITIVE** | **`mounts`**: bind source содержит **`.ssh`**, **`.aws`**, **`.kube`**, **`docker.sock`** и т.п. | Утечка хост-секретов / захват docker daemon | devcontainer, compose под devcontainer |
| **SEC-DEVCONTAINER-METADATA-LABEL** | В **Dockerfile** в **`LABEL devcontainer.metadata=`** есть lifecycle-ключи (`postCreateCommand`, …) | Скрытое автовыполнение относительно json в репо | `Dockerfile`, `*.Dockerfile` |
| **SEC-YAML-PYTHON-TAG** | В workflow/compose/MCP yaml встречаются теги **`!!python/object`** и аналоги | Небезопасная десериализация при «не тем» парсере | `.github/workflows/**`, `docker-compose*.yml`, `mcp*.yaml` |
| **SEC-GHA-RUN-INJECT-INPUT** | В **`run:`** встроены **`$\{\{ inputs.* \}\}` / `github.event.*`** (недоверенный контекст) без вынесения в **`env:`** | [Script injection](https://docs.github.com/en/actions/concepts/security/script-injections) | `.github/workflows/**` |
| **SEC-GHA-ACTION-NO-SHA** | **`uses: owner/repo@ref`** для сторонних action: **ref не 40-char SHA** (тег/ветка/короткий SHA) | Подмена тега | workflows |
| **SEC-GHA-WRITE-UNTRUSTED-CODE** | **`permissions`** с **write** + checkout/запуск кода с **head форка** / `pull_request_target` без изоляции | Pwn request класс | workflows |
| **SEC-GHA-CACHE-POISON** | Один и тот же ключ **`actions/cache`** записывается из **недоверенного** workflow и читается **привилегированным** | Cache poisoning | workflows |
| **SEC-NPM-INSTALLSCRIPT-SURFACE** | В lockfile **`hasInstallScript: true`** у пакетов без политики **ignore-scripts / onlyBuiltDependencies / trustedDependencies** | Install-time RCE цепочка | `package-lock.json`, `pnpm-lock.yaml` + `package.json` |
| **SEC-PNPM-ALLOW-ALL-BUILDS** | **`dangerouslyAllowAllBuilds: true`** в pnpm config | Авто-запуск всех build-скриптов при обновлении графа | `pnpm-workspace.yaml`, `.npmrc` |
| **SEC-COREPACK-NO-HASH** | **`packageManager`** без **`+sha…`** (политика воспроизводимости) | Подмена менеджера пакетов | корневой `package.json` |
| **SEC-PY-EXTRA-INDEX-HOST** | **`--extra-index-url` / `PIP_EXTRA_INDEX_URL` / `tool.uv.extra-index-url`** → хост **∉ allowlist** или **http** | Dependency confusion ([pip](https://pip.pypa.io/en/stable/cli/pip_install.html#examples), [PEP 708](https://peps.python.org/pep-0708/)) | `requirements*.txt`, `pyproject.toml`, CI env |
| **SEC-PY-GIT-NO-SHA** | **`git+https://…@branch`** без **полного SHA** в зависимостях (политика) | Неповторяемый / подменяемый исходник | requirements, `pyproject.toml`, `uv.lock` |
| **SEC-ML-REMOTE-URL** | **DVC** `remote url`, **`MLFLOW_TRACKING_URI`**, **`WANDB_BASE_URL`**, **`HF_ENDPOINT`**: **http** или private/metadata хост в committed файлах | SSRF / эксфильтрация трекинга | `.dvc/config`, compose, Helm, `.env.example` |
| **SEC-OBS-EXPORT-INLINE-SECRET** | В OTEL/observability YAML **литералы** `api_key` / `Authorization` / `DD_API_KEY` / `LANGSMITH_API_KEY` без `${…}` / secretKeyRef | Утечка ключей в git | `otel-collector*.yaml`, compose |
| **SEC-VECTOR-HTTP-URL** | **`http://`** в URL/env для **Pinecone / Qdrant / Weaviate / Chroma** (не localhost по политике) | Ключи и эмбеддинги по сети без TLS | compose, Helm, `config*.yml` |
| **SEC-EXTISM-HOSTS-NULL** | В **Extism** manifest **`allowed_hosts`: `null`** (полный интернет) | Неконтролируемый исходящий HTTP плагина | `extism.json`, manifest по [Extism](https://extism.org/docs/concepts/manifest) |

**Связь с текущим lintai:** фактические коды `SEC*` — только в **[SECURITY_RULES.md](SECURITY_RULES.md)**.

---

## Тир A — сильная гигиена (security-релевантно или смежно)

| ID | Правило | Заметка |
|----|---------|---------|
| **SEC-SKILL-METADATA** | `metadata` только string → string | [agentskills.io/specification](https://agentskills.io/specification) |
| **SEC-SKILL-ALLOWED-TOOLS** | `allowed-tools`: одна строка, токены через пробел | там же |
| **SEC-MCP-INPUTSCHEMA-OBJECT** | **`inputSchema.type === "object"`** (проза MCP tools) | [MCP server tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) |
| **SEC-OAS-BUNDLE** | OpenAPI 3.x по **OAS 3.1 schema** | [spec.openapis.org](https://spec.openapis.org/oas/v3.1/schema) |
| **SEC-GHA-PWN-REQUEST** | `pull_request_target` + checkout недоверенного ref | [GitHub Security Lab](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) |
| **SEC-PLUGIN-PATH** | Пути в **plugin.json**: относительные, без **`..`**, без absolute (Cursor submit / Anthropic) | [Cursor Plugins](https://cursor.com/docs/reference/plugins), [Anthropic plugins](https://docs.anthropic.com/en/docs/claude-code/plugins-reference) |
| **SEC-PLUGIN-AGENT** | В plugin agent **нет** `hooks`, `mcpServers`, `permissionMode` во frontmatter | [Anthropic — Agents in plugins](https://docs.anthropic.com/en/docs/claude-code/plugins-reference#agents) |
| **SEC-OWASP-LOCK** | LLM03: манифест + lock по политике | [LLM03 Supply Chain](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) |
| **SEC-OWASP-TOOLS** | LLM06: не `"tools": "*"` / пустой allowlist (политика JSON) | [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) |
| **SEC-RAG-CHUNK** | При явных ключах: `chunk_size > 0`, `chunk_overlap < chunk_size` | [LangChain TextSplitter](https://reference.langchain.com/python/langchain-text-splitters/base/TextSplitter/), [LlamaIndex SentenceSplitter](https://developers.llamaindex.ai/python/framework-api-reference/node_parsers/sentence_splitter/) — **gated**, medium FP без контекста ключей |
| **SPEC-GHA-YAML-ON-KEY** | В GHA YAML корневой ключ **`on:`** в кавычках / валидный триггер (избежать boolean `on` в YAML 1.1) | [Workflow syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions), [yaml bool](https://yaml.org/type/bool.html) |
| **SPEC-YAML-MERGE-REVIEW** | Наличие **`<<:` merge** в compose/workflow — флаг на **ручной аудит** порядка слияния | [YAML merge](https://yaml.org/type/merge.html), [Compose merge](https://docs.docker.com/reference/compose-file/merge/) |
| **SEC-YAML-ANCHOR-PERMISSIONS** | **Anchors (`&`/`*`) + merge** рядом с **`permissions:`** / **`env:`** в GHA | Скрытые capabilities при ревью | `.github/workflows/**` |
| **SEC-TPL-JINJA-IN-PROMPT** | В `**/prompts/**`, `SKILL.md`, `**/templates/**`: delimiters **`\{\{`/`\{%`** без документированной политики **raw / variables-only** | SSTI + [LLM01](https://genai.owasp.org/llmrisk/llm01/) indirect | см. [WSTG SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07_Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection) |
| **SEC-TPL-BUILD-FROM-STRING** | **`Template(` / `from_string` / `render_template_string`** с шаблоном из f-string/concat из ненадёжного источника | Классический SSTI | `**/*.py` (и стек-специфика) |
| **SEC-NPM-BIN-SHADOW** | **`bin`** в `package.json` с именами **`node`/`npm`/`npx`/…** (PATH confusion) | Вредоносный shim при отключённых scripts | `package.json` — [Socket](https://socket.dev/blog/npm-bin-script-confusion) |
| **SEC-OVERRIDES-DRIFT** | Есть **`overrides`/`resolutions`**, но lockfile **не отражает** ожидаемые версии (эвристика) | Ложное чувство патча CVE | `package.json`, locks |
| **SEC-PY-PACKAGE-ALLOWLIST** | Имена пакетов после **PyPA normalization** ∉ org **allowlist** / эвристика typosquat | Slopsquatting | [name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/) |
| **SEC-PY-SETUP-EXEC** | **`exec`/`eval`/`compile`** в **`setup.py`** (узкий scope файла) | Произвольный код при установке | `setup.py` — [secure installs](https://pip.pypa.io/en/stable/topics/secure-installs.html) |
| **SEC-REDO-CONFIG-REGEX** | Значения **`pattern`/`regex`/`regexp`** с **вложенными квантификаторами** / `(a\|aa)+` | ReDoS на длинных документах | RAG/agent yaml — [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html), [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) |
| **SEC-TOOL-ID-ASCII** | **`operationId` / tool `name`**: политика **ASCII** machine id (`^[A-Za-z][A-Za-z0-9_-]*$` или house style) | Homoglyph / policy bypass | tools json, OpenAPI — [UTS #39](https://www.unicode.org/reports/tr39/) |
| **SEC-TOOL-ID-NO-IGNORABLE** | В tool id нет **ZWSP / bidi / default-ignorable** (UTS #39 profile) | Разные ключи при одинаковом «виде» | JSON tools |
| **SEC-CURSOR-IGNORE-NOT-BOUNDARY** | Док/политика: не считать **`.cursorignore`** единственной защитой секретов (**terminal/MCP** всё ещё читают файлы) | Ложное чувство защиты | [Ignore file](https://cursor.com/docs/reference/ignore-file), [Agent Security](https://cursor.com/docs/agent/security) |
| **SEC-CURSOR-MCP-ENVFILE** | В **`.cursor/mcp.json`**: **`envFile`** на богатый `.env` + нет review политики; литералы в **`env`/`headers`** вместо **`${env:}`** | Расширение blast radius stdio MCP | [MCP Cursor](https://cursor.com/docs/context/mcp) |
| **SEC-CLAUDE-BYPASS-IN-REPO** | В committed **`.claude/settings.json`**: **`defaultMode: bypassPermissions`** (project) | Избыточная agency в shared config | [Permissions](https://docs.anthropic.com/en/docs/claude-code/permissions) |
| **SEC-CLAUDE-HOOK-PATH** | **Hooks `command`**: absolute path / `~/` **без** **`$CLAUDE_PROJECT_DIR`** для team scripts | Невоспроизводимость / подмена пути | [Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) |
| **SEC-CLAUDE-HOOK-HTTP** | HTTP-hook: **не https** или URL **вне** политики **`allowedHttpHookUrls`** | MITM / неконтролируемый exfil | [Hook configuration](https://docs.anthropic.com/en/docs/claude-code/settings#hook-configuration) |
| **SEC-ENV-TEMPLATE-FAKE-SECRET** | **`.env.example`**: значения в формате **реальных** секретов (entropy / `AKIA…` / `sk_live`) | Сканеры, копипаст в prod | [OWASP Secrets](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| **SEC-DIRENV-ESCAPE-ROOT** | **`.envrc`**: `source`/`dotenv` на **absolute** пути, **`/etc`**, `$HOME`, выход из корня репо | Чтение чужих секретов | `.envrc` |
| **SEC-VECTOR-COMPOSE-BIND** | Compose: образы **qdrant/weaviate/chroma** с **`ports: "6333:6333"`** без **`127.0.0.1:`** (политика) | Публикация БД в LAN | `docker-compose*.yml` |
| **SEC-LLM-TRACE-HIDE-OFF** | В prod-профиле: **`LANGSMITH_HIDE_INPUTS=false`** (и аналоги) при **`LANGSMITH_TRACING=true`** | Промпты/PII в SaaS трейсах | [LangSmith mask](https://docs.langchain.com/langsmith/mask-inputs-outputs) |
| **SEC-OTEL-LLM-NO-SCRUB** | Коллектор с LLM-телеметрией: только **`batch`** без **redact/transform** процессоров (эвристика) | PII в экспортёре | [OTEL sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/) |

---

## Тир B — спецификация и качество (полезно, не headline security)

| ID | Правило | Заметка |
|----|---------|---------|
| **SPEC-SKILL** | Agent Skills: поля `name` / `description` / `compatibility`, dirname, уникальность | [Specification](https://agentskills.io/specification) |
| **SPEC-SERVER-JSON** | `server.json`, `$schema`, `remotes[].type` ∈ `streamable-http` \| `sse` | [Registry](https://modelcontextprotocol.io/registry/quickstart), [Remote servers](https://modelcontextprotocol.io/registry/remote-servers) |
| **SPEC-MCP-CLIENT** | Формы **Cursor** `mcpServers`, **VS Code** `servers`+`inputs`, **Claude** `.mcp.json` | [Cursor MCP](https://cursor.com/docs/context/mcp), [VS Code](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration), [Claude Code MCP](https://docs.anthropic.com/en/docs/claude-code/mcp) |
| **SPEC-AGENTS-SIZE** | Codex: лимит байт цепочки инструкций | [AGENTS.md guide](https://developers.openai.com/codex/guides/agents-md/) |
| **SPEC-CURSOR-MDC** | YAML frontmatter `.mdc`, `alwaysApply` boolean, `globs` sequence | [Cursor Rules](https://cursor.com/docs/context/rules) |
| **SPEC-SBOM** | Наличие + валидация **CycloneDX** / SPDX + **NTIA minimum** при артефактах моделей | [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/), [NTIA minimum elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) |
| **SPEC-CLAUDE-SETTINGS-SCHEMA** | Committed **`.claude/settings.json`** содержит **`$schema`** → [SchemaStore claude-code-settings](https://json.schemastore.org/claude-code-settings.json) | [Settings](https://docs.anthropic.com/en/docs/claude-code/settings) |
| **SPEC-EXTISM-MANIFEST** | Валидация JSON манифеста Extism по [upstream schema](https://raw.githubusercontent.com/extism/extism/main/manifest/schema.json) | [Manifest](https://extism.org/docs/concepts/manifest) |
| **SPEC-WASI-IMPORTS** | Декларированный **world/capabilities** согласован с фактическими импортами компонента (ручной + `wasm-tools`) | [Component worlds](https://component-model.bytecodealliance.org/design/worlds.html), [wasi-cli imports](https://raw.githubusercontent.com/WebAssembly/wasi-cli/main/imports.md) |

---

## CVE / advisory (закрепить в semver-политике линтера)

| Компонент | Диапазон / условие | Исправление | Источник |
|-----------|-------------------|-------------|----------|
| **mcp-remote** (npm) | уязвимые версии по advisory | **≥ 0.1.16** | [CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514), [GHSA-6xpm-ggf7-wc3p](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) |
| **@modelcontextprotocol/sdk** | **1.10.0–1.25.3** | **≥ 1.26.0** | [CVE-2026-25536](https://nvd.nist.gov/vuln/detail/CVE-2026-25536), [GHSA-345p-7cg4-v4c7](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-345p-7cg4-v4c7) |
| **VS Code + Copilot** (экосистема Microsoft) | по NVD/MSRC для **CVE-2026-21518** | по [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21518) | [CVE-2026-21518](https://nvd.nist.gov/vuln/detail/CVE-2026-21518) |
| **Cursor CLI** | по **GHSA** / NVD | по advisory | [CVE-2025-61592](https://nvd.nist.gov/vuln/detail/CVE-2025-61592), [GHSA-v64q-396f-7m79](https://github.com/cursor/cursor/security/advisories/GHSA-v64q-396f-7m79) |
| **Cursor** (desktop/agent) | по **GHSA** / NVD | по advisory | [CVE-2026-31854](https://nvd.nist.gov/vuln/detail/CVE-2026-31854), [GHSA-hf2x-r83r-qw5q](https://github.com/cursor/cursor/security/advisories/GHSA-hf2x-r83r-qw5q) |

*Точные CPE/диапазоны меняются — в CI сверяйте NVD/MSRC на дату сборки.*

---

## Минимальные наборы

### Только security gate (расширенный ~14)

1. SEC-MCP-CVE (+ **SEC-PRODUCT-CVE** если сканируете IDE)  
2. SEC-MCP-URL + **SEC-MCP-SSRF-LITERAL** + **SEC-MCP-TLS-BYPASS**  
3. SEC-MCP-SECRETS  
4. SEC-MCP-SHADOW + SEC-TOOLS-COLLISION + **SEC-MCP-TOOL-REQ**  
5. SEC-OPENAI-STRICT + SEC-OPENAI-STRICT-REQ + SEC-ANTHROPIC-STRICT  
6. SEC-MD-BIDI-ZWSP + SEC-MD-DANGEROUS-URL + SEC-MD-PEM + SEC-MD-PIPE-SHELL  
7. SEC-LOCKFILE + SEC-MCP-REMOTE-VARS  
8. **SEC-MCP-LAUNCH** + **SEC-HOOK-AUTOEXEC** + **SEC-PRECOMMIT-PIN**  
9. **SEC-COPILOT-FM** + **SEC-COPILOT-4K** (если используете Copilot instructions в репо)  
10. **SEC-PLUGIN-PATH** + **SEC-PLUGIN-AGENT** (если шипятся плагины)  
11. **SEC-ML-ARTIFACT** (если в репо веса моделей)  
12. SEC-JSONSCHEMA-META  

### Расширение «monorepo + CI + devcontainer» (вторая волна)

- **Devcontainer:** SEC-DEVCONTAINER-INIT-HOST, SEC-DEVCONTAINER-FEATURE-REGISTRY, SEC-DEVCONTAINER-BIND-SENSITIVE, SEC-DEVCONTAINER-METADATA-LABEL  
- **GitHub Actions:** SEC-GHA-RUN-INJECT-INPUT, SEC-GHA-ACTION-NO-SHA, SEC-GHA-WRITE-UNTRUSTED-CODE, SEC-GHA-CACHE-POISON (+ уже SEC-GHA-PWN-REQUEST)  
- **YAML supply chain:** SEC-YAML-PYTHON-TAG, SEC-YAML-ANCHOR-PERMISSIONS  
- **JS/TS installs:** SEC-NPM-INSTALLSCRIPT-SURFACE, SEC-PNPM-ALLOW-ALL-BUILDS, SEC-COREPACK-NO-HASH  
- **Python deps:** SEC-PY-EXTRA-INDEX-HOST, SEC-PY-GIT-NO-SHA  
- **ML/vectors/observability:** SEC-ML-REMOTE-URL, SEC-VECTOR-HTTP-URL, SEC-VECTOR-COMPOSE-BIND, SEC-OBS-EXPORT-INLINE-SECRET  
- **Плагины WASM:** SEC-EXTISM-HOSTS-NULL  

### Security + спека

Добавить **SPEC-SKILL**, **SPEC-SERVER-JSON**, **SPEC-MCP-CLIENT**, **SEC-OAS-BUNDLE**, **SEC-RAG-CHUNK** (с gate по ключам), **SPEC-SBOM** при моделях; при **Claude Code** в git — **SPEC-CLAUDE-SETTINGS-SCHEMA**; при **GHA** — **SPEC-GHA-YAML-ON-KEY**; при **Extism** — **SPEC-EXTISM-MANIFEST**.

---

## Ограничения статического линтера

- **Семантический prompt injection** в свободном prose — низкая точность как единственный gate.  
- **Confused deputy / token passthrough** в OAuth — в основном **рантайм**; статика ловит только грубые литералы и антипаттерны в коде.  
- **RAG chunk** — разные единицы (токены vs символы); линтить только с явной меткой или известным классом конфига.

---

## Первоисточники (расширенный список)

| Тема | URL |
|------|-----|
| MCP security (spec 2025-11-25) | https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices |
| MCP schema (raw) | https://raw.githubusercontent.com/modelcontextprotocol/specification/main/schema/2025-11-25/schema.json |
| OWASP LLM Top 10 2025 | https://genai.owasp.org/llm-top-10/ |
| MITRE ATLAS | https://atlas.mitre.org/ , ATLAS.yaml https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml |
| ENISA Threat Landscape 2025 | https://www.enisa.europa.eu/sites/default/files/2026-01/ENISA%20Threat%20Landscape%202025_v1.2.pdf |
| NIST AI 600-1 PDF | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf |
| Copilot custom instructions | https://docs.github.com/en/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot |
| Copilot code review 4000 | https://docs.github.com/en/copilot/tutorials/use-custom-instructions |
| HF Hub — unsafe weight formats | https://huggingface.co/docs/hub/main/security-pickle |
| Safetensors | https://huggingface.co/docs/safetensors/index |
| PyTorch `torch.load` | https://docs.pytorch.org/docs/stable/generated/torch.load.html |
| PyTorch GHSA (weights_only history) | https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6 |
| pre-commit freeze | https://pre-commit.com/#pre-commit-autoupdate-options |
| VS Code Workspace Trust | https://code.visualstudio.com/docs/editor/workspace-trust |
| CycloneDX validate CLI | https://github.com/CycloneDX/cyclonedx-cli |
| Dev Containers / VS Code remote | https://code.visualstudio.com/docs/devcontainers/containers |
| GHA script injections | https://docs.github.com/en/actions/concepts/security/script-injections |
| GHA hardening (pin SHA) | https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions |
| GitHub Security Lab (cache, pwn requests) | https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/ |
| Corepack packageManager + hash | https://github.com/nodejs/corepack/blob/main/README.md |
| pnpm dangerouslyAllowAllBuilds | https://pnpm.io/settings#dangerouslyallowallbuilds |
| DVC configuration | https://dvc.org/doc/user-guide/project-structure/configuration |
| MLflow env vars | https://mlflow.org/docs/latest/python_api/mlflow.environment_variables.html |
| W&B environment variables | https://docs.wandb.ai/models/track/environment-variables |
| OTEL config best practices | https://opentelemetry.io/docs/security/config-best-practices/ |
| Unicode TR36 / UTS #39 | https://www.unicode.org/reports/tr36/ , https://www.unicode.org/reports/tr39/ |
| Cursor ignore file | https://cursor.com/docs/reference/ignore-file |
| Claude Code settings / hooks | https://docs.anthropic.com/en/docs/claude-code/settings |
| Qdrant security | https://qdrant.tech/documentation/guides/security/ |
| Weaviate authentication | https://weaviate.io/developers/weaviate/configuration/authentication |

*(Плюс: Agent Skills, Registry, Cursor Rules, OpenAI function calling, Anthropic structured outputs, Codex AGENTS.md, CVE-2021-42574, TR36, OpenAPI 3.1, JSON Schema 2020-12, GitHub Actions hardening.)*

---

## См. также

- **[SECURITY_RULES.md](SECURITY_RULES.md)** — фактические коды `SEC*` и shipped rules.  
- **[RULE_QUALITY_POLICY.md](RULE_QUALITY_POLICY.md)** — политика точности и promotion.  
- **[POSITIONING_AND_SCOPE.md](POSITIONING_AND_SCOPE.md)** — границы продукта.
