import pytest

# UA без слова HeadlessChrome — иначе сервер выдаст BOT
DESKTOP_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)

# В Docker headless Chromium не добавляет sec-ch-ua автоматически,
# поэтому передаём их явно — как это делает реальный Chrome
CHROME_HINTS = {
    "accept-language": "ru-RU,ru;q=0.9",
    "sec-ch-ua": '"Google Chrome";v="130", "Chromium";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}


@pytest.mark.positive
def test_real_chrome_desktop(antibot_server, browser, base_url):
    context = browser.new_context(
        user_agent=DESKTOP_CHROME_UA,
        locale="ru-RU",
        extra_http_headers=CHROME_HINTS,
    )
    try:
        page = context.new_page()
        response = page.goto(f"{base_url}/")
        assert response is not None
        payload = response.json()

        assert payload["verdict"] == "REAL_BROWSER", payload["analysis"]["reasons"]
        assert payload["blocked"] is False
        assert payload["analysis"]["bot_score"] < 2
    finally:
        context.close()


@pytest.mark.positive
def test_real_mobile_browser(antibot_server, browser, playwright, base_url):
    # Pixel 5 — Chromium-движок. iPhone не шлёт sec-ch-ua — получил бы SUSPICIOUS.
    device = playwright.devices["Pixel 5"]
    mobile_ua = (
        "Mozilla/5.0 (Linux; Android 13; Pixel 5) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/130.0.0.0 Mobile Safari/537.36"
    )
    mobile_hints = {
        **CHROME_HINTS,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
    }
    context = browser.new_context(
        **{**device, "user_agent": mobile_ua},
        locale="ru-RU",
        extra_http_headers=mobile_hints,
    )
    try:
        page = context.new_page()
        response = page.goto(f"{base_url}/")
        assert response is not None
        payload = response.json()

        assert payload["verdict"] == "REAL_BROWSER", payload["analysis"]["reasons"]
        assert payload["blocked"] is False
        assert payload["analysis"]["bot_score"] < 2
    finally:
        context.close()
