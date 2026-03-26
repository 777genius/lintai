# Capabilities / Scope Manifest (feature)

> Статус: **зафиксировано как feature**  
> Цель: дать детерминированный способ описывать “что этот артефакт имеет право делать”, чтобы lintai мог строго проверять **несоответствия Claims ↔ Capabilities** и резко снижать FP.

## Зачем

“Семантические” проблемы (intent vs behavior) решаются без LLM-as-judge через:
- **Claims**: что артефакт *заявляет* (политики/ограничения/“no network”, “read-only”).
- **Capabilities**: что артефакт *фактически может/пытается делать* (hooks, scripts, tool schemas, конфиги).
- **Mismatch rules**: строгие правила вида “заявлено X, но наблюдается Y”.

## Где задаётся policy/manifest

### 1) На уровне конкретного skill (предпочтительно)

В `SKILL.md` — через **frontmatter** (YAML/TOML) с декларацией capabilities.

Минимальная схема (MVP):
- `capabilities.network`: `none | outbound:https | outbound:any | inbound`
- `capabilities.exec`: `none | shell | subprocess`
- `capabilities.fs`: `read`/`write` + scope путей (globs)
- `capabilities.secrets`: `none | read-env | read-files` (+ scope)
- `capabilities.mcp`: разрешённые классы tool-операций (например: `read_file`, `http_get`, `exec`, …)

Пример (YAML frontmatter):

```yaml
---
capabilities:
  network: outbound:https
  exec: none
  fs:
    read:
      - "./"
    write: []
  secrets:
    read_env: false
    read_files: []
---
```

### 2) На уровне папки/проекта (policy для репо)

В `lintai.toml` (или отдельный policy-файл, подключаемый из `lintai.toml`) — чтобы задавать ожидания по путям:
- “в этой папке exec запрещён”
- “network разрешён только тут”
- “hooks допустимы только с allowlist команд”

## Аннотации для MCP (расширение schema)

Feature: **MCP tool schema annotations** — расширение `mcp.json`, где каждому tool можно добавить:
- `capabilities`
- `data_access`
- `side_effects`

Цель: lintai может сравнивать “tool declares read-only” vs “tool does write/exec/network”.

## Расширение manifest для Cursor Plugins

Feature: **Cursor plugin manifest extension** — в `plugin.json` / `hooks.json` (или рядом) декларативно описывать:
- какие hooks существуют и на каких событиях запускаются
- какие операции допустимы (network/exec/fs/secrets)

Цель: строгий mismatch-анализ между декларацией и фактическими scripts/hooks.

## Принципы (важно)

- Manifest/policy — **опционален**, но если он задан, mismatch правила работают **строго** (high confidence).
- Это не “доверие на слово”: lintai всегда показывает доказательства (где claim и где capability).
- Никаких облачных LLM: всё **offline-first** и **deterministic**.

## Precedence и конфликты (зафиксировано)

Если заданы оба уровня (project policy + per-skill frontmatter), применяем строгий precedence:

1. **Project policy** (в `lintai.toml` / подключаемый policy-файл) — источник истины для репозитория.
2. **Per-skill frontmatter** — дополняет/уточняет в рамках политики проекта.

Если frontmatter противоречит project policy:
- по умолчанию: **warning** с явным описанием конфликта
- по настройке проекта: **deny** (строгий режим)

