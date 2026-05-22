import pytest

# Полный набор браузерных заголовков — чтобы антидетект-тест сработал именно по UA,
# а не из-за отсутствия sec-ch-ua
BROWSER_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "ru-RU,ru;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "sec-ch-ua": '"Chromium";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}


@pytest.mark.negative
@pytest.mark.parametrize(
    "user_agent, expected_reason",
    [
        ("python-requests/2.31.0", "python-requests"),
        ("curl/8.4.0", "curl"),
        ("Go-http-client/1.1", "Go-http-client"),
        ("", "Missing User-Agent"),
    ],
    ids=["python-requests", "curl", "go-http-client", "empty-ua"],
)
def test_known_bot_clients(http_client, user_agent, expected_reason):
    response = http_client.get("/", headers={"user-agent": user_agent})
    payload = response.json()

    assert payload["verdict"] == "BOT", payload["analysis"]["reasons"]
    assert payload["blocked"] is True
    assert any(expected_reason in r for r in payload["analysis"]["reasons"])


@pytest.mark.negative
def test_headless_playwright_default(antibot_server, browser, base_url):
    # Без подмены UA Playwright оставляет "HeadlessChrome" в строке — сервер даёт +9
    context = browser.new_context()
    try:
        page = context.new_page()
        response = page.goto(f"{base_url}/")
        assert response is not None
        payload = response.json()

        assert payload["verdict"] == "BOT", payload["analysis"]["reasons"]
        assert payload["blocked"] is True
        assert any("Headless" in r for r in payload["analysis"]["reasons"])
    finally:
        context.close()


@pytest.mark.negative
def test_antidetect_browser_ua(http_client):
    indigo_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/130.0.0.0 Safari/537.36 IndigoBrowser/1.2"
    )
    response = http_client.get("/", headers={"user-agent": indigo_ua, **BROWSER_HEADERS})
    payload = response.json()

    assert payload["verdict"] == "ANTIDETECT_BROWSER", payload["analysis"]["reasons"]
    assert payload["blocked"] is True
    assert payload["analysis"]["scores"]["is_antidetect"] >= 3
