# lintai — Glossary (canonical)

Цель: единые термины, чтобы будущие изменения не путали.

## Artifacts

- **Skill**: артефакт навыка агента (обычно `SKILL.md`), который содержит инструкции/описание/иногда frontmatter.
- **Instructions**: instruction-файлы для агентов/IDE (например `CLAUDE.md`, `AGENTS.md`, `.windsurfrules`, и т.п.).
- **MCP**: конфиги MCP-серверов и их tool schemas (например `mcp.json`, `claude_desktop_config.json`).
- **Cursor Plugin**: пакет плагина Cursor, включающий manifest, rules/skills/commands/agents, hooks и т.п.

## Semantics without LLM

- **Claims**: заявленные ограничения/политики (“no network”, “read-only”, “no secrets”).
- **Capabilities**: фактические возможности/поведение, наблюдаемое из hooks/scripts/schemas/config.
- **Policy / Manifest**: декларация capabilities/scope на уровне проекта или артефакта.
- **Mismatch rule**: правило, сравнивающее Claims ↔ Capabilities и выдающее finding при несоответствии.

## Core types

- **Finding**: результат правила (diagnostic). SARIF/CI-friendly.
- **Location**: позиция finding в файле. Source of truth = byte-span; line/col могут быть derived/optional.
- **Fix**: данные для автоисправления (Safe/Unsafe/Suggestion).
- **stable_key**: стабильный ключ для дедупликации finding’ов. Не зависит от wording сообщения.
- **fingerprint**: хэш/идентификатор для SARIF/CI, вычисляется на выходе из stable полей (включая stable_key).

## Severity model

- **Category**: “что это за класс проблемы” (security/critical/…).
- **Severity**: “что делать” (allow/warn/deny), влияет на CI/exit code.
- **Confidence**: уверенность (low/medium/high).

## Architecture

- **`lintai-api`**: стабильный контракт (types + traits).
- **Engine**: оркестратор пайплайна (discovery → parse → check → suppress → aggregate → output).
- **Provider**: реализация `FileRuleProvider` или `WorkspaceRuleProvider`, источник правил (native/YAML/WASM). `RuleProvider` остаётся legacy compatibility bridge.
- **Adapters/Parsers**: FORMAT vs DOMAIN: парсинг форматов отдельно от доменной интерпретации.
