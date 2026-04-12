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
- **`threat-review`** is the explicit opt-in lane for malicious, credential-bearing, or spyware-like signals that may still be structurally strong but should not define the main `preview` story or the quiet default UX
- Эвристическое правило может быть полезным, но пока оно зависит от phrase/domain marker lists, оно не считается canonical `Stable`.

## Graduation gates

- `Stable` требует **completed graduation metadata**, а не только `tier = Stable` в metadata.
- `Preview` требует **explicit blocker** и понятные promotion requirements.
- Для security rules graduation proof живёт рядом с rule spec:
  - rationale
  - deterministic signal basis
  - linked malicious corpus ids
  - linked benign corpus ids
  - structured evidence requirement
  - remediation review state
- Hard gates enforce это через tests; prose сама по себе не считается достаточной защитой от дрейфа quality bar.

## Product presentation lanes

Для сайта, release narrative и "первого экрана" rules делим ещё и по product роли:

- **Flagship rules**:
  - правила с лучшим signal/noise на реальных community cohort
  - подходят для homepage, demos, top-rules docs и first-run examples
  - типичный профиль: structural, легко объясняются, remediation очевиден
- **Domain-sensitive rules**:
  - правила полезные, но сильно зависящие от offensive-security, research или teaching контекста
  - не должны быть "лицом продукта", даже если часто матчятся
  - их ценность показываем через precision notes и cohort-specific reports, а не через hero placement

На текущем срезе это означает:

- `Flagship quiet-default/default-adjacent`: `SEC340`, `SEC329`
- `Flagship sidecar`: `SEC352`, `SEC324`
- `Domain-sensitive`: `SEC102`, `SEC313`, `SEC335`, `SEC347`, `SEC348`, `SEC349`, `SEC351`

`SEC347` остаётся сильным shipped preview rule, но после quiet-default hardening его больше не стоит подавать как first-screen example наравне с committed config rules.

## Flagship promotion track

Для `Flagship` rules нужен ещё один промежуточный статус мышления, даже если в runtime lifecycle его пока нет:

- **stable-candidate**:
  - правило уже сильное продуктово и по precision
  - правило ещё не переведено в `Stable`
  - remaining work касается formal graduation package, а не raw detector usefulness

Минимальные требования для такого статуса:

- structural или иным образом детерминированный сигнал
- linked malicious и benign corpus cases
- regression coverage на positive и negative формы
- внешний field signal вне "слишком чистого" official cohort
- отсутствие текущего FP cluster в последнем ручном разборе

Текущий основной stable-candidate:

- сейчас нет отдельного highlighted stable-candidate; `SEC352` уже shipped как stable `governance` rule и больше не относится к preview promotion track

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
