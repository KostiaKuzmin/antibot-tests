# Автотесты для антибот-сервера

## Быстрый старт

```bash
# установи зависимости
pip install -r requirements.txt
playwright install

# запусти тесты
pytest -v
```

Или через Docker:
```bash
docker compose -p antibot up --build --abort-on-container-exit
```

---

## Что здесь

Сервер анализирует HTTP-запросы и выносит вердикт: человек это, бот или что-то подозрительное.

Я написал 7 тестов, которые проверяют что сервер правильно угадывает:

### Позитивные (должны пройти как люди)
- **test_real_chrome_desktop** — браузер Chrome на Windows
- **test_real_mobile_browser** — браузер Chrome на Android

### Негативные (должны заблокироваться как боты)
- **test_known_bot_clients** × 4 — python-requests, curl, Go, пустой User-Agent
- **test_headless_playwright_default** — Playwright в headless режиме (UA выдаёт себя)
- **test_antidetect_browser_ua** — антидетект браузер (Indigo)

### Граничные (сложные случаи)
- **test_suspicious_chrome_without_client_hints** — Chrome UA, но без нужных заголовков → SUSPICIOUS
- **test_rate_limit_high_frequency** — 35 запросов подряд → заблокировать

---

## Почему именно эти тесты

Нужно было проверить три типа:
1. **Реальные браузеры** — Playwright реально управляет браузером, отправляет все нужные заголовки
2. **Боты** — httpx с контролируемыми заголовками, чтобы имитировать разные боты
3. **Пограничные случаи** — случаи где не очень понятно

Тесты 1 и 4 — зеркала: в одном подменяю User-Agent (проходит), в другом нет (блокируется). Это доказывает что сервер действительно работает на проверку строки "HeadlessChrome".

