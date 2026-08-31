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
| Решить crackme / пароль | Symbolic / concolic (`argus agent` / `solve`) |
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

Главные принципы:

1. **Равноправие платформ (Linux и Windows — граждане первого класса)**:
   - **Движок Linux**: ELF64/32, DWARF, секции раскрутки стека `.eh_frame`, GNU ABI, PLT/GOT, загрузка соседних библиотек через `LD_LIBRARY_PATH`.
   - **Движок Windows**: PE32/PE32+, каталоги функций исключений `.pdata` x64 ($O(1)$ поиск функций), Win64 ABI, импорты/экспорты IAT/EAT, поиск DLL через Windows `PATH`, нативная поведенческая smoke-проверка `.exe`.
2. **Высокопроизводительная архитектура**:
   - Нулевое оверхед-выделение памяти `SparseMemory` (срезы секций вместо гигантских Python-словарей на 30–50 млн элементов — мгновенно масштабируется на бинарники 50–100+ МБ).
   - Векторизованный NumPy-поиск xref'ов и rodata, отрабатывающий за миллисекунды на тяжелых десктопных приложениях.
   - Ускоренный проход Capstone с точечной фильтрацией инструкций.
3. **Форматы — адаптеры** — сегодня ELF/PE; агент думает задачами, а не «рецептами под одну ОС».
4. **Текст агента не закрывает задачу** — статус определяется только результатами тулов (`verify.ok`, проверенный план патчей и т.д.).
5. **Пайплайн gate transform** — `argus_slice` → `patch_plan` → `argus_apply_plan` → verify. Одиночные freestyle-патчи такие задачи не завершают.
6. **Динамический синтез инструментов и расширяемость** — если встроенных инструментов Argus недостаточно или агент зашел в тупик, он может вызвать `argus_exec` для написания собственных Python-скриптов (с использованием `argus`, `pefile`, `capstone`, `z3`) или выполнения shell-команд (`pip install`, `curl`) для динамической загрузки или создания недостающих утилит.
7. **Memory — это RAG** — похожие кейсы лишь подсказки (hints); локально всё равно требуется верификация.

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

### 1. Полноценный LLM-агент (рекомендуется)

**Gemini (AI Studio)** — ключ: [aistudio.google.com/apikey](https://aistudio.google.com/apikey):

```bash
export GEMINI_API_KEY="AIza..."
export ARGUS_LLM_PROVIDER=gemini
export ARGUS_GEMINI_MODEL=gemini-3.5-flash-lite

argus agent --provider gemini "найди и проанализируй логику проверки" samples/fauxware_fla -v
```

**OpenAI-совместимый** (OpenAI, OpenRouter, Gemini OpenAI shim):

```bash
export ARGUS_OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export ARGUS_OPENAI_API_KEY="AIza..."
export ARGUS_OPENAI_MODEL="gemini-3.5-flash-lite"

argus agent --provider openai "найди и проанализируй логику проверки" samples/fauxware -v
```

Агент при необходимости находит связанные модули, патчит только **work copy** и закрывает задачи по evidence тулов.

### 2. Классический CLI

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
