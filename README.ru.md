# Argus

**Argus** — это AI-инструментарий для реверс-инжиниринга: вы описываете задачу обычным языком, Argus сам исследует бинарь настоящими инструментами, меняет только рабочую копию и проверяет, что результат действительно держится.

> **Модель предлагает. Детерминированные тулы исполняют. Рантайм / математика верифицируют.**

Это **не** «крякер лицензий» и **не** Ghidra с чатом. Это небольшая лаборатория: LLM-агент собирает пайплайн из атомарных операций (найти строки, xref’ы, поднять код, построить план патча, применить, проверить) и оставляет сертификат того, что реально доказано.

---

## Зачем это

| Нужно… | Argus умеет… |
|--------|----------------|
| Понять stripped ELF/PE | Строки, xref’ы, pseudo-C, CFG |
| Аккуратно сменить поведение | `patch_plan` → apply → verify (байты + smoke) |
| Решить crackme / пароль | Symbolic / concolic (`argus ai` / agent) |
| Снять OLLVM-подобное CFF | Unflatten + опциональный патч + verify |
| Учиться на прошлых кейсах | Общая case memory (подсказки, не истина) |

**Не цель (0.2.x):** полный unpack VMProtect/Themida «как коммерческий тул»; «100% на любом бинаре без подсказки».

---

## Как это работает (картинка в голове)

```
Ваша задача (обычный язык)
    → LLM-агент выбирает tools
        → gate_scan / find / lift / patch / apply_plan / …
            → рабочая копия бинаря (оригинал не трогаем)
                → verify (байты, опционально поведение)
                    → задача «done» только по evidence тулов
```

Главные правила:

1. **Форматы — адаптеры** — сегодня ELF/PE; агент думает задачами, а не «рецептами под один вендор».
2. **Текст агента не закрывает задачу** — статус из результатов тулов (`verify.ok`, план из slice и т.д.).
3. **Пайплайн gate transform** — `argus_slice` → `patch_plan` → `argus_apply_plan` → verify. Одиночные freestyle-патчи такие задачи не завершают.
4. **Memory — это RAG** — похожие кейсы лишь hints; локально всё равно нужно verify.

Подробнее: [docs/ARGUS_VISION.md](docs/ARGUS_VISION.md).

---

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,concrete]"
# опционально: pip install -e ".[memory]"   # клиент общей памяти кейсов
# опционально: pip install torch            # GNN-proposer
```

Точка входа CLI: `argus`.

---

## Быстрый старт

### 1. Естественный язык (без облачной LLM)

Локальный / regex-роутер — удобно для smoke:

```bash
argus ai "дай пароль для админа" samples/fauxware_fla
```

### 2. Настоящий агент (рекомендуется)

**Gemini (AI Studio)** — ключ: [aistudio.google.com/apikey](https://aistudio.google.com/apikey):

```bash
export GEMINI_API_KEY="AIza..."
export ARGUS_LLM_PROVIDER=gemini
export ARGUS_GEMINI_MODEL=gemini-2.0-flash

argus agent --provider gemini "дай пароль для админа" samples/fauxware_fla -v
```

**OpenAI-compatible** (OpenAI, OpenRouter, Gemini OpenAI shim):

```bash
export ARGUS_OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export ARGUS_OPENAI_API_KEY="AIza..."
export ARGUS_OPENAI_MODEL="gemini-2.0-flash"

argus agent --provider openai "дай пароль" samples/fauxware -v
```

Агент при необходимости находит связанные модули, патчит только **work copy** и закрывает задачи по evidence тулов.

### 3. Классический CLI

```bash
argus analyze samples/fauxware
argus solve samples/fauxware --deobf
argus deobf samples/fauxware_fla -f authenticate --patch /tmp/out --all-cff --verify
argus certify samples/fauxware_fla -f authenticate --solve
argus eval --corpus samples --json /tmp/corpus.json
```

Корпус сэмплов: [samples/MANIFEST.md](samples/MANIFEST.md).

---

## Память кейсов (опционально, по умолчанию включена если установлена)

Общий опыт на `https://argus.cloud.badkiko.ru` после `pip install -e ".[memory]"`.

**Приватность:** каждый прогон агента может отправить структурированный отчёт (SHA256 + basename, arch/format, текст задачи, стратегии, outcome) и получить похожие кейсы как подсказки. **Сырые бинарники не загружаются.**

```bash
argus agent "убери проверку" ./app                # memory вкл. по умолчанию
argus agent --no-memory "…" ./app                 # выкл. на один прогон
export ARGUS_MEMORY=0                             # выкл. глобально
export ARGUS_MEMORY_URL=https://your-server.example

argus memory search "stripped elf gate"
argus memory stats
```

Деплой бэкенда: [argus-backend/README.md](argus-backend/README.md).

---

## Карта пакетов

| Пакет | Роль |
|-------|------|
| `argus.llm` | Агент, tools, intent, session |
| `argus.ask` / `argus.nl` | Hint → ответ / lift / patch |
| `argus.find_slice` | Gate scan → `patch_plan` |
| `argus.apply_plan` | Применить план + verify |
| `argus.binary` | Загрузчики ELF/PE |
| `argus.disasm` | Capstone CFG |
| `argus.symbolic` / `argus.concrete` | Z3 / Unicorn |
| `argus.deobf` | CFF, MBA, частичный VMP |
| `argus.prove` | Сертификаты / уровни верификации |
| `argus.memory` | Клиент удалённой памяти кейсов |
| `argus.ir` | Заготовка формат-агностичного IR |

---

## Тесты

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

---

## Языки

- English: [README.md](README.md)
- Русский (этот файл): [README.ru.md](README.ru.md)

## Лицензия

MIT
