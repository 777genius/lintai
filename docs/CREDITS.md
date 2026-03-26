# CREDITS — зависимости и заимствования

> **Назначение:** единая таблица «компонент → crate / репо → лицензия → что переносим или как используем».  
> **Обязательно:** перед мержем каждого порта сверять лицензию в upstream (текст ниже — ориентир, не юридическая консультация).  
> **Связано:** [VISION.md](VISION.md), [LINTAI_PLAN.md](../../research/LINTAI_PLAN.md), [legal-licensing-grid.md](../../research/legal-licensing-grid.md).  
> **Аудит:** глубокие проходы crates.io + upstream LICENSE + структура репозиториев + RUSTSEC + интеграция YARA-X (**четыре волны параллельных агентов**, последняя — 2026-03-25).

**Легенда колонки «Тип»:**  
- **Crate** — зависимость из crates.io / git.  
- **Port** — переносим логику/данные/правила в код lintai (с атрибуцией).  
- **Optional** — внешний бинарь / подпроцесс.  
- **Ref** — идеи, таксономии, документация (без копирования кода).

**Колонка «Вариант»:** если указано **A / B** (или **C**), оба пути допустимы — выбор фиксируется в ADR или в `Cargo.toml` features.

---

## 1. Rust crates — спорные места: два (или три) пути

Ниже только зоны, где «одного очевидного» крейта нет. Остальные (clap, miette, rayon, toml_edit, insta, schemars) без изменений — см. §1b.

### 1.1 Markdown

| Вариант | Crate / источник | Лицензия (SPDX) | Когда выбирать | Тип |
|--------|-------------------|-----------------|----------------|-----|
| **A** (рекомендуем по умолчанию для линтера) | [pulldown-cmark](https://github.com/raphlinus/pulldown-cmark) | MIT | Pull-parser `Event` + `into_offset_iter()` — быстро, мало аллокаций, точные байтовые диапазоны для findings. | Crate |
| **B** | [comrak](https://github.com/kivikakk/comrak) | BSD-2-Clause | Нужно готовое AST + GFM «как у GitHub»; **минимизировать default features** (тяжёлый стек, напр. syntect). Если когда-либо рендерите **HTML** из недоверенного Markdown — держать свежую версию (исторически [RUSTSEC-2021-0026](https://rustsec.org/advisories/RUSTSEC-2021-0026.html), [RUSTSEC-2021-0063](https://rustsec.org/advisories/RUSTSEC-2021-0063.html)). Для линтера без HTML-рендера поверхность ниже. | Crate |
| **C** | [markdown](https://github.com/wooorm/markdown-rs) (markdown-rs) | MIT | GFM/frontmatter/MDX в одном стеке; сверять активность релизов на [crates.io](https://crates.io/crates/markdown). | Crate |

### 1.2 YAML → Serde (не использовать deprecated `serde_yaml`)

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [yaml_serde](https://github.com/yaml/yaml-serde) ([crates.io](https://crates.io/crates/yaml_serde)) | MIT OR Apache-2.0 | Официальный serde-слой от YAML.org поверх libyaml; крейт **молодой** — оценить тестами и `cargo audit` перед production. | Crate |
| **B** | [serde_yaml_bw](https://github.com/bourumir-wyngs/serde-yaml-bw) | MIT OR Apache-2.0 | **Budget / billion laughs / лимиты алиасов** для недоверенного frontmatter; цена — `unsafe`/libyaml внизу стека. | Crate |
| **C** | [serde_yaml2](https://github.com/zim32/serde_yaml2) | MIT OR Apache-2.0 | **Pure Rust** (yaml-rust2); релизы реже, чем у транзитивов — пиновать версии. | Crate |

**Не путать с [serde_yml](https://crates.io/crates/serde_yml)** (другое имя): в advisory-db есть **RUSTSEC-2025-0068** (unsound) — **не использовать**; это не `serde_yaml2`.

### 1.3 JSON с комментариями (JSONC)

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [json_comments](https://github.com/tmccombs/json-comments-rs) + [serde_json](https://github.com/serde-rs/json) | Apache-2.0 + (MIT OR Apache-2.0) | Только **чтение**: стрип комментариев → serde; **фуззить** граничные строки (последний релиз крейта давно). | Crate |
| **B** | [jsonc-parser](https://github.com/dprint/jsonc-parser) | MIT | **CST / правки** с сохранением комментариев; активные релизы на момент аудита. | Crate |

*Третий путь:* [biome_json_parser](https://crates.io/crates/biome_json_parser) (MIT OR Apache-2.0) — если уже тянете экосистему Biome. [microsoft/jsonc-parser](https://github.com/microsoft/jsonc-parser) — TypeScript, не crate.

### 1.4 Редактирование YAML (auto-fix)

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [yaml-edit](https://github.com/jelmer/yaml-edit) | Apache-2.0 | Lossless (Rowan); **мало adopters** на registry — пилот и регрессионные тесты диффов. | Crate |
| **B** | [yaml-rust2](https://github.com/Ethiraric/yaml-rust2) или [saphyr](https://github.com/saphyr-rs/saphyr) | MIT OR Apache-2.0 | parse → emit; `saphyr` в **0.0.x** (нестабильный semver). Новые фичи — смотреть README upstream (миграция с yaml-rust2). | Crate |

### 1.5 SARIF 2.1

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [serde-sarif](https://github.com/psastras/sarif-rs) | MIT | Дефолт для serde; golden-тесты против GitHub Code Scanning / потребителей SARIF. | Crate |
| **B** | Собственные `struct` + serde | (ваша) | Узкое подмножество полей, нулевая зависимость от чужого breaking API. | — |
| **C** | [sarif_rust](https://github.com/khalidelborai/sarif_rust) | MIT OR Apache-2.0 | Альтернатива builder/streaming; **мало скачиваний** — сравнить покрытие схемы перед выбором. | Crate |

### 1.6 Обход файлов с учётом ignore

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [ignore](https://github.com/BurntSushi/ripgrep/tree/master/crates/ignore) | Unlicense OR MIT | Де-факто стандарт: `WalkBuilder`, gitignore. | Crate |
| **B** | [gix-ignore](https://github.com/GitoxideLabs/gitoxide) | MIT OR Apache-2.0 | Уже на **gix-*** для всего Git-слоя. | Crate |

### 1.7 LSP (фаза)

| Вариант | Crate / источник | Лицензия | Когда выбирать | Тип |
|--------|-------------------|----------|----------------|-----|
| **A** | [tower-lsp-server](https://github.com/IWANABETHATGUY/tower-lsp-server) + `lsp-types` | MIT | Новый Tower-LSP стек, релизы 2025+; см. [TECHNICAL_DECISIONS.md](../../research/TECHNICAL_DECISIONS.md). | Crate |
| **B** | [lsp-server](https://crates.io/crates/lsp-server) (орбита rust-analyzer) | MIT OR Apache-2.0 | Минимальный JSON-RPC/LSP без tower — больше кода у вас, меньше «магии». | Crate |
| **C** | [tower-lsp](https://github.com/ebkalderon/tower-lsp) | MIT | **Наследие:** последний релиз 2023 — только для совместимости, не старт нового сервера без причины. | Crate |

---

## 1b. Rust crates — без спорного выбора (кратко)

| Компонент | Crate / источник | Лицензия | Тип | Что используем |
|-----------|-------------------|----------|-----|----------------|
| JSON | [serde](https://github.com/serde-rs/serde), [serde_json](https://github.com/serde-rs/json) | MIT OR Apache-2.0 | Crate | Строгий JSON без комментариев. |
| TOML edit / fix | [toml_edit](https://github.com/toml-rs/toml_edit) | MIT OR Apache-2.0 | Crate | Auto-fix TOML. |
| YARA deep scan | [yara-x](https://github.com/VirusTotal/yara-x) (crate `yara-x`) | **BSD-3-Clause** — см. [Cargo.toml upstream](https://github.com/VirusTotal/yara-x/blob/main/Cargo.toml) | Crate | Feature `--deep`; правила как bytes / compile at build. **MSRV** у свежих релизов высокий (в workspace указано **1.89+** на момент аудита) — учитывать в политике MSRV lintai. Тянет **wasmtime** (много записей в advisory-db) — `cargo audit` + пин версий. Детали фич и **musl / внешний CLI** — §1e. |
| CLI | [clap](https://github.com/clap-rs/clap) | MIT OR Apache-2.0 | Crate | Подкоманды, флаги. |
| Диагностики | [miette](https://github.com/zkat/miette) | Apache-2.0 | Crate | Ошибки CLI. |
| Прогресс | [indicatif](https://github.com/console-rs/indicatif) | MIT | Crate | Длинные сканы. |
| Параллелизм | [rayon](https://github.com/rayon-rs/rayon) | MIT OR Apache-2.0 | Crate | Параллельный обход. |
| JSON Schema | [schemars](https://github.com/GREsau/schemars) | MIT | Crate | Схема конфига. |
| Снапшоты | [insta](https://github.com/mitsuhiko/insta) | Apache-2.0 | Crate | Регрессии вывода. |

---

## 1c. Зрелость и безопасность крейтов (ориентир, не замена CI)

Снимок по публичным метрикам и обсуждениям на **2026-03**; точные цифры downloads на [crates.io](https://crates.io) устаревают за дни.

| Зона | Ориентир | Обязательное действие |
|------|-----------|------------------------|
| YAML serde | `yaml_serde` — очень новый трек; `serde_yaml2` — редкие релизы при большом DL транзитивов; `serde_yaml_bw` — частые релизы, libyaml/unsafe | Перед production: сравнить пару вариантов на **фуззинге** frontmatter и лимитах размера. |
| JSONC **A** | `json_comments` — давно без релиза | Тесты на граничные `//` и строки с `#`. |
| SARIF | `serde-sarif` — зрелый; `sarif_rust` — мало adopters | Golden SARIF на реальных потребителях. |
| **Все перечисленные** | RUSTSEC меняется с версиями | **`cargo audit`** (или эквивалент) на каждом релизе + **`cargo deny`** при политике лицензий. |
| Альтернативы в libyaml-мире | упоминаются `serde_yaml_ng`, `serde_norway` и др. | Проверять [rustsec.org](https://rustsec.org) на момент выбора. |

**Два стратегических выбора под YAML (не юридика, инженерия):**

| Подход | Суть | Уверенность | Надёжность |
|--------|------|-------------|------------|
| **1** | Ветка **pure Rust** (`yaml-rust2` / `saphyr` + serde-слой) — меньше класса C/libyaml в цепочке. | 7/10 | 8/10 для снижения класса нативных CVE |
| **2** | Ветка **libyaml** (`serde_yaml_bw`, возможно `yaml_serde`) — жёсткие лимиты входа, пин версий, audit. | 6/10 | 7/10 при дисциплине CI |

---

## 1d. RUSTSEC / advisory-db (ориентир по имени крейта)

Источник правды — [rustsec/advisory-db](https://github.com/rustsec/advisory-db) и **`cargo audit`** (или эквивалент) на **вашем** `Cargo.lock`. Ниже — типичные попадания для стека линтера; не exhaustive.

| Крейт / тема | Advisory | Тип / заметка |
|--------------|----------|----------------|
| **serde_yml** (отдельное имя на crates.io) | [RUSTSEC-2025-0068](https://rustsec.org/advisories/RUSTSEC-2025-0068.html) | unsound; **не** `serde_yaml2` / **не** `serde_yaml` |
| **serde_yaml** (если ещё в дереве) | [RUSTSEC-2018-0005](https://rustsec.org/advisories/RUSTSEC-2018-0005.html) | DoS / неконтролируемая рекурсия; патчи в современных версиях — лучше уйти с deprecated цепочки |
| **yaml-rust** | [RUSTSEC-2024-0320](https://rustsec.org/advisories/RUSTSEC-2024-0320.html) | unmaintained (часто транзитив через старый serde_yaml) |
| **unsafe-libyaml** | [RUSTSEC-2023-0075](https://rustsec.org/advisories/RUSTSEC-2023-0075.html) | unsound на части платформ → **≥ 0.2.10** |
| **comrak** | [RUSTSEC-2021-0026](https://rustsec.org/advisories/RUSTSEC-2021-0026), [RUSTSEC-2021-0063](https://rustsec.org/advisories/RUSTSEC-2021-0063.html) | XSS / format injection при пути «→ HTML» |
| **wasmtime** | несколько ID в DB (обновляются) | транзитив **yara-x** — смотреть только по lockfile |
| **yaml-rust2**, **yara-x**, **tower-lsp**, **pulldown-cmark** | нет отдельной папки в DB на момент сверки | всё равно запускать `cargo audit` |

**Два режима в CI**

| Режим | Уверенность | Надёжность |
|-------|-------------|------------|
| **1** — `cargo audit` (+ при политике `cargo deny`) на каждый PR | 9/10 | 9/10 |
| **2** — только ручной чеклист без автоматизации | 5/10 | 4/10 |

---

## 1e. YARA-X: фичи, musl, in-process vs внешний `yr`

- **Дефолтные features** зависят от **опубликованного тега** крейта (на **v1.14.0** в `default` входят в т.ч. `linkme`, `default-modules`, …). На ветке `main` upstream может отличаться (напр. `inventory` vs `linkme`) — не копировать «с главной» вслепую. Канон: [lib/Cargo.toml](https://github.com/VirusTotal/yara-x/blob/v1.14.0/lib/Cargo.toml), обзор: [docs.rs — features](https://docs.rs/crate/yara-x/latest/features).
- **Минимизация библиотеки:** `default-features = false`; включать только нужные `*-module`; по возможности без лишнего `generate-proto-code` (см. описание фичи в `lib/Cargo.toml`). **`parallel-compilation`** по умолчанию off — перед включением см. [VirusTotal/yara-x#182](https://github.com/VirusTotal/yara-x/issues/182).
- **musl / статическая линковка:** риск связки **wasmtime + musl** — обсуждение [bytecodealliance/wasmtime#8898](https://github.com/bytecodealliance/wasmtime/issues/8898); для lintai с **linux-musl** в матрице — **обязательный CI** на целевом triple.
- **Редкие архитектуры:** ограничения wasmtime/cranelift — [VirusTotal/yara-x#108](https://github.com/VirusTotal/yara-x/issues/108). **Windows ARM64:** зрелость таргета у wasmtime — [стабильность / tiers](https://docs.wasmtime.dev/stability-tiers.html), [релиз-ноты](https://bytecodealliance.org/articles/wasmtime-26.0).
- **CLI отдельно:** официальный поток — крейт [yara-x-cli](https://crates.io/crates/yara-x-cli), док: [установка YARA-X](https://virustotal.github.io/yara-x/docs/intro/installation/).

| Стратегия | Суть | musl / статика основного бина | Размер / артефакты | Сопровождение |
|-----------|------|------------------------------|-------------------|---------------|
| **A** | In-process `yara-x`, `default-features = false`, минимум модулей | уверенность **6/10**, надёжность **6/10** — проверять на musl | один бинарь, но тяжёлый | один dependency graph |
| **B** | Подпроцесс **`yr`** / бинарь из [GitHub Releases](https://github.com/VirusTotal/yara-x/releases) или `cargo install yara-x-cli` | уверенность **8/10**, надёжность **7/10** для тонкого статического CLI | два артефакта, проще уменьшить основной бинарь | матрица версий + UX установки |

При **поставке** `yr` вместе с продуктом — сохранять требования **BSD-3-Clause** для этого бинаря (NOTICE / тексты лицензий).

---

## 2. Портируемые правила и датасеты

| Компонент | Репозиторий | SPDX (проверить ветку) | Тип | Что переносим / заметки |
|-----------|-------------|------------------------|-----|-------------------------|
| Правила + сканеры (Rust) | [ryo-ebata/cc-audit](https://github.com/ryo-ebata/cc-audit) | MIT — [LICENSE](https://github.com/ryo-ebata/cc-audit/blob/main/LICENSE) | Port | **Код правил:** `src/rules/builtin/*.rs`; движок: `src/rules/engine.rs`, `types.rs`, `custom.rs`, `heuristics.rs`. Сканеры: `src/engine/scanners/`. Данные: `data/cve-database.json`, `data/malware-signatures.json`. Док: `docs/RULES.md`, примеры: `examples/rules/custom-rules.yaml`. |
| YARA (skills) | [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Apache-2.0 — [LICENSE](https://github.com/cisco-ai-defense/skill-scanner/blob/main/LICENSE) | Port | `skill_scanner/data/packs/core/yara/*.yara`; `.../signatures/*.yaml`; `.../pack.yaml`; политика: `skill_scanner/data/default_policy.yaml`. |
| YARA (MCP) | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 — [LICENSE](https://github.com/cisco-ai-defense/mcp-scanner/blob/main/LICENSE) | Port | Правила: **`mcpscanner/data/yara_rules/`** (`*.yara`, `*.yar` — загрузчик в `mcpscanner/core/analyzers/yara_analyzer.py`). Константа `DEFAULT_YARA_RULES_DIRECTORY`, override `MCP_SCANNER_YARA_RULES_DIR`. Маппинг угроз: `mcpscanner/threats/`. **Не** предполагать идентичность дерева skill-scanner. |
| Секреты (YAML rules) | [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) | Apache-2.0 — [LICENSE](https://github.com/praetorian-inc/noseyparker/blob/main/LICENSE), [NOTICE](https://github.com/praetorian-inc/noseyparker/blob/main/NOTICE) | Port / data | **Источник правил:** `crates/noseyparker/data/default/builtin/rules/*.yml`, манифесты `.../rulesets/`. Формат: [docs/RULES.md](https://github.com/praetorian-inc/noseyparker/blob/main/docs/RULES.md). Крейт сборки: `crates/noseyparker-rules/`. В YAML **часто нет** отдельного SPDX в каждом файле — атрибуция по **репо + NOTICE**. |
| Секреты (TOML + источник истины) | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT — [LICENSE](https://github.com/gitleaks/gitleaks/blob/master/LICENSE) | Port / data | Артефакт: [`config/gitleaks.toml`](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml). **Канонические определения:** `cmd/generate/config/rules/*.go`, `base/`, `utils/`, см. `cmd/generate/config/main.go`. Для атрибуции портов указывать **и** генератор, и TOML. |
| Большой набор regex | [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) | **CC BY-SA 4.0** — [LICENSE.md](https://github.com/mazen160/secrets-patterns-db/blob/master/LICENSE.md) | Port / data | См. §2a. Данные: `db/`, `datasets/`. |
| Supply chain / Semgrep-стиль | [DataDog/guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 — [LICENSE](https://github.com/DataDog/guarddog/blob/main/LICENSE), [NOTICE](https://github.com/DataDog/guarddog/blob/main/NOTICE) | Port / data | `guarddog/analyzer/sourcecode/*.yml`, `*.yar`; `guarddog/analyzer/metadata/`. |
| PI / YARA | [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) | Apache-2.0 — [LICENSE](https://github.com/deadbits/vigil-llm/blob/main/LICENSE) | Port / data | `data/yara/*.yar`, `data/regex/`, `data/prompts/`. |
| CVE / таксономия MCP | [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Apache-2.0 — [LICENSE](https://github.com/Tencent/AI-Infra-Guard/blob/main/LICENSE) | Ref / Port | Таксономия MCP01–M10, YAML CVE; перепроверять NOTICE в корне. |
| OWASP | [OWASP ASI / MCP Top 10](https://owasp.org/) | По страницам | Ref | Маппинг rule id; без копирования кода. |
| Semgrep ruleset (vendor) | **A:** [apiiro/malicious-code-ruleset](https://github.com/apiiro/malicious-code-ruleset) | MIT — [LICENSE](https://github.com/apiiro/malicious-code-ruleset/blob/main/LICENSE) | Port / Optional | Отдельный публичный набор правил. |
| PR / app | **B:** [apiiro/PRevent](https://github.com/apiiro/PRevent) | MIT — [LICENSE](https://github.com/apiiro/PRevent/blob/main/LICENSE) | Ref / Optional | Продукт вокруг GitHub; в CREDITS — только явно портированные части. |

---

## 2a. Два подхода там, где лицензия «ломает» простую вставку

### secrets-patterns-db (CC BY-SA 4.0)

| Подход | Суть | Уверенность | Надёжность для закрытого бинарника |
|--------|------|-------------|-------------------------------------|
| **1** | Соблюдать **BY-SA** (атрибуция + SA на Adapted Material при Share). См. [legal code §3(a)–3(b)](https://creativecommons.org/licenses/by-sa/4.0/legalcode); FAQ CC про адаптации — ориентир, не замена counsel. | 6–7/10 | 4/10 |
| **2** | **Не копировать** выражения из `db/`; независимые паттерны / другие лицензии. | 6/10 | 8/10 при процессе и при необходимости юрист |

### Semgrep: три слоя (не смешивать в одной строке CREDITS)

| Артефакт | Репозиторий | Лицензия | Заметка |
|----------|-------------|----------|---------|
| Движок CLI | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-only — [LICENSE](https://github.com/semgrep/semgrep/blob/develop/LICENSE) | Подпроцесс — см. ниже; док: [semgrep.dev/docs/licensing](https://semgrep.dev/docs/licensing). |
| Официальный корпус правил | [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) | **Semgrep Rules License v1.0** — [LICENSE](https://github.com/semgrep/semgrep-rules/blob/develop/LICENSE) → [правила на сайте](https://semgrep.dev/legal/rules-license) | **Не** «всё MIT»; порт/вендоринг правил — читать текст лицензии на каждый набор. |
| Сторонние ruleset’ы | разные репо | MIT / Apache / другое | Указывать **SPDX по каждому** источнику. |

| Подход | Суть | Уверенность | Надёжность (enterprise) |
|--------|------|-------------|-------------------------|
| **1** | Только **подпроцесс** к `semgrep`, без линковки LGPL в процесс lintai; в дистрибутиве отдельно документировать двоичный движок и лицензии правил. | 7/10 | 6/10 |
| **2** | Линковка LGPL — **§6 LGPL-2.1** (замена библиотеки, объектники и т.д.). | 8/10 при compliance | 5/10 операционно |

*Ранее:* формулировка «отдельные `.yml` могут быть под другими лицензиями» — верна; для **semgrep-rules** дефолт уже **не** LGPL, а **Semgrep Rules License v1.0**.

---

## 2b. Дополнительные OSS-источники (расширение CREDITS при портировании)

| Источник | URL | Лицензия (проверить) | Тип | Заметка для lintai |
|----------|-----|----------------------|-----|---------------------|
| TruffleHog | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | **AGPL-3.0** — [LICENSE](https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE) | Ref / Optional | Сильные verified-детекторы; **AGPL** — не встраивать в проприетарный бинарь без юр. обзора; subprocess/отдельный сервис или только идеи. |
| detect-secrets | [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | Apache-2.0 — [LICENSE](https://github.com/Yelp/detect-secrets/blob/master/LICENSE) | Ref / Port | Плагины, baseline workflow — паттерны и процесс. |
| git-secrets | [awslabs/git-secrets](https://github.com/awslabs/git-secrets) | Apache-2.0 — [LICENSE](https://github.com/awslabs/git-secrets/blob/master/LICENSE) | Ref / Port | AWS-ориентированные deny-листы / хуки. |
| Checkov | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 — [LICENSE](https://github.com/bridgecrewio/checkov/blob/main/LICENSE) | Ref | IaC вокруг деплоя агентов (Terraform/K8s/Docker), не MCP-специфика. |
| GitHub Secret Scanning | [документация паттернов](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns) | — | Ref | Таксономия провайдеров; **нет** единого OSS-дампа regex для редистрибуции. |
| OpenSSF Scorecard | [ossf/scorecard](https://github.com/ossf/scorecard) | Apache-2.0 — [LICENSE](https://github.com/ossf/scorecard/blob/main/LICENSE) | Ref | Сигналы зрелости репо (branch protection, releases) — **идеи для policy**, не YAML ruleset под SKILL.md. |
| OpenSSF Allstar | [ossf/allstar](https://github.com/ossf/allstar) | Apache-2.0 — [LICENSE](https://github.com/ossf/allstar/blob/main/LICENSE) | Ref | Орг. политики GitHub — чеклист supply chain вокруг репо со skills. |
| OSV Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 — [LICENSE](https://github.com/google/osv-scanner/blob/master/LICENSE) | Optional / Ref | CVE/OSV + опционально allowlist лицензий (`--licenses`); не правила для markdown skills. |
| OSV.dev | [google/osv.dev](https://github.com/google/osv.dev) | Apache-2.0 | Ref | API/данные уязвимостей — supply chain, не парсер skills. |
| OWASP dep-scan | [owasp-dep-scan/dep-scan](https://github.com/owasp-dep-scan/dep-scan) | MIT — [LICENSE](https://github.com/owasp-dep-scan/dep-scan/blob/master/LICENSE) | Ref | SBOM/VEX, сценарии CI — доки и идеи. |
| zizmor | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) | MIT — [LICENSE](https://github.com/zizmorcore/zizmor/blob/main/LICENSE) | Ref / Optional | Статический анализ **GitHub Actions** (workflow YAML) → SARIF; релевантно **CI вокруг** репозитория skills. |
| Ramparts (Javelin) | [getjavelin/ramparts](https://github.com/getjavelin/ramparts) | Apache-2.0 — [LICENSE](https://github.com/getjavelin/ramparts/blob/main/LICENSE) | Port / Ref | YARA + эвристики под MCP; можно портируемо брать **слой правил/идеи**, без обязательного LLM-пути. |
| mcphound | [tayler-id/mcphound](https://github.com/tayler-id/mcphound) | MIT — [LICENSE](https://github.com/tayler-id/mcphound/blob/main/LICENSE) | Ref | Таксономия атак между MCP-серверами — threat model, переформулировать в свои правила. |
| skill-audit | [dabit3/skill-audit](https://github.com/dabit3/skill-audit) | MIT — [LICENSE](https://github.com/dabit3/skill-audit/blob/main/LICENSE) | Ref | Категории security/quality для SKILL.md — спецификация проверок, не чужой движок. |
| SecScanMCP | [zakariaf/SecScanMCP](https://github.com/zakariaf/SecScanMCP) | **AGPL-3.0** — [LICENSE](https://github.com/zakariaf/SecScanMCP/blob/main/LICENSE) | Ref / Optional | Много YARA под MCP; **copyleft** — не вшивать в закрытый бинарь без юр. обзора; идеи или subprocess. |
| OpenSSF package-analysis | [ossf/package-analysis](https://github.com/ossf/package-analysis) | Apache-2.0 — [LICENSE](https://github.com/ossf/package-analysis/blob/main/LICENSE) | Ref | Анализ npm/PyPI/… — supply chain, не IDE rules. |
| Grype | [anchore/grype](https://github.com/anchore/grype) | Apache-2.0 — [LICENSE](https://github.com/anchore/grype/blob/main/LICENSE) | Optional | Скан уязвимостей по SBOM/образам — рядом с lintai в CI, не конкурент по skills. |
| skills.sh audits | [skills.sh/audits](https://skills.sh/audits) | — (не репозиторий) | Ref | **Reference-only:** UX отчётов (колонки риска); не копируемый rule pack. |

**Две интерпретации «где живут правила»** (для чеклиста атрибуции):

| # | Интерпретация | Практика |
|---|----------------|----------|
| **1** | Только «данные» (yaml/yara/toml) | Указывать конкретные каталоги в таблице §2. |
| **2** | Всё, что задаёт детект (вкл. генераторы Go в Gitleaks, движок cc-audit) | Расширить NOTICE и ссылки на **исходники определений**, не только сгенерированный TOML. |

---

## 2c. Чеклист для maintainers (NOTICE / совмещение лицензий)

*Не юридическая консультация — гигиена поставки.*

- **Apache-2.0 + вшитые YARA/YAML:** текст лицензии + **§4(c)** сохранение уведомлений; если upstream дал **NOTICE** — включить релевантные строчки в ваш **NOTICE** ([текст лицензии](https://www.apache.org/licenses/LICENSE-2.0.txt); [ASF howto](https://www.apache.org/dev/licensing-howto.html)).
- **MIT + BSD-3-Clause + Apache в одном бинаре:** общий **NOTICE** или `THIRD_PARTY_NOTICES.md` + папка `licenses/*` с полными текстами.
- **yara-x (BSD-3-Clause)** в MIT/Apache продукте: совместимо при **сохранении условий BSD** (copyright, disclaimer) в NOTICE — статическая линковка в Rust = редистрибуция зависимости.
- **CC BY-SA:** см. §2a; при сомнении — путь **без копирования** выражений из БД.

| Практика поставки | Уверенность «как у индустрии» | Надёжность для аудита |
|-------------------|------------------------------|------------------------|
| **A** | Один корневой `NOTICE` + `licenses/*` | 8/10 | 8/10 |
| **B** | SPDX/SBOM в сборке **и** человекочитаемый NOTICE | 7/10 | 9/10 |

---

## 3. Опциональные внешние инструменты

| Компонент | Репозиторий | Лицензия | Тип | Как используем |
|-----------|-------------|----------|-----|----------------|
| Движок Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-only | Optional | Подпроцесс; см. §2a. |
| Корпус правил Semgrep | [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) | Semgrep Rules License v1.0 | Optional / Ref | Не предполагать MIT; читать [rules license](https://semgrep.dev/legal/rules-license). |
| Секреты в CI | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Optional | Доп. слой. |
| Универсальный CI | [MegaLinter](https://github.com/oxsecurity/megalinter) | MIT | Optional | Custom linter → бинарь lintai. |
| YARA-X CLI (`yr`) | [VirusTotal/yara-x releases](https://github.com/VirusTotal/yara-x/releases) / [yara-x-cli](https://crates.io/crates/yara-x-cli) | BSD-3-Clause | Optional | Альтернатива in-process `yara-x` (§1e-B); см. [документацию установки](https://virustotal.github.io/yara-x/docs/intro/installation/). |
| OSV Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Optional | CVE/OSV рядом с lintai в CI; см. §2b. |

---

## 4. Документация и стандарты

| Источник | Назначение |
|----------|------------|
| [OASIS SARIF 2.1](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) | Контракт вывода. |
| [Model Context Protocol](https://modelcontextprotocol.io/) | Семантика MCP. |
| [agentskills.io](https://agentskills.io/) | SKILL.md и родственные форматы. |

---

## 5. Порядок работы с этим файлом

1. Зависимость в `Cargo.toml` → §1 / §1b / §1c / **§1d** / **§1e**; при смене варианта A/B — ADR + changelog.  
2. Порт правил → §2 (или §2b) + commit upstream + при необходимости **NOTICE**.  
3. Каждый релиз: **`cargo audit`** (см. §1d), при политике — **`cargo license`** / SBOM; сверка LICENSE default branch.  
4. Квартально: актуальность URL, MSRV тяжёлых крейтов (`yara-x`, §1e), новые RUSTSEC (в т.ч. **serde_yml** vs **serde_yaml2**, **wasmtime** транзитивы).

---

*Последнее обновление: 2026-03-25 (четвёртый глубокий проход: RUSTSEC/advisory-db, расширение §2b OpenSSF/OSV/zizmor/MCP OSS, YARA-X features/musl/wasmtime vs внешний `yr`).*
