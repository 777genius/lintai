# Rule Quality Policy (strict)

> Статус: **зафиксировано**  
> Цель: делать только **надёжные** правила (низкий FP) без “хардкода текста” и без магии.

## Что считаем “строго надёжным” правилом

Правило считается “строго надёжным”, если оно:
- **Детерминированное** (одни и те же входы → один и тот же результат).
- **Объяснимое**: finding всегда содержит конкретное “доказательство” (спаны/строки/фрагменты), а не “кажется опасно”.
- **Основано на фактах**, а не на тонких текстовых формулировках:
  - предпочтение: hooks/scripts/конфиги/schemas/структура документа/контекст regions
  - избегать: “если встречается фраза X” как единственный триггер
- **Контекстно-осведомлённое**: учитывает `regions` (например, code blocks vs normal text), чтобы не матчить примеры.
- **Имеет тесты**: минимум 1 positive + 1 negative, плюс регрессионные кейсы из корпуса.

## Stable vs Preview lane

- **`Stable`** reserved only for **structural / high-precision** checks:
  - hooks/scripts/config structure
  - explicit regions/zones boundaries
  - deterministic key/value or token observations
- **`Preview`** is the staging lane for **heuristic / text-led** checks:
  - suspicious phrases in descriptive text
  - suspicious host markers
  - env-name heuristics or similar signals that may need FP tuning
- Эвристическое правило может быть полезным, но пока оно зависит от phrase/domain marker lists, оно не считается canonical `Stable`.

## Запрещённые подходы (anti-patterns)

- “Хардкод текста” как основа правила: правила не должны опираться на одну-две фразы, которые легко перефразировать и которые дают FP.
- “Скрытые” правила без доказательств (нет ссылок на конкретные места).
- Правила, которые нельзя стабильно протестировать и которые зависят от окружения/сети.

## Source of truth for native rules

- Metadata, detection surface, tier, remediation message и candidate fix должны жить **рядом с правилом** в одном native rule spec.
- Provider не должен держать отдельные `match rule_code => remediation`.
- Per-artifact signals/analyzers вычисляются **один раз на файл**, а rules читают уже готовые observations.

## Как делаем семантику без LLM

Для сложных кейсов используем **Claims ↔ Capabilities mismatch**:
- Claims: что заявлено (frontmatter/policy/описание ограничений)
- Capabilities: что реально может/пытается делать (hooks/scripts/tool schemas)
- Мismatch: строгие проверки несоответствия + корреляция сигналов (confidence)

См. `FEATURE_CAPABILITIES_MANIFEST.md`.

## Реалистичные целевые объёмы “строго надёжных” правил

Фиксируем ожидания, чтобы не гнаться за количеством:

- **v0.1**: **40–80** строго надёжных правил (high precision).
- **v0.2–v1.0**: **150–250** строго надёжных правил (при наличии корпуса и регрессий).

## Auto-fix: реалистично и безопасно

В security-линтере большинство “починок” не может быть полностью безопасным. Фиксируем ожидания:

- **Safe auto-fix**: примерно **10–25** правил.
- **Unsafe (только с флагом)**: примерно **15–40** правил.
- Остальное: **Suggestion** (IDE/репорт), без автоматического применения.
