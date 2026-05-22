import pytest

DESKTOP_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)


@pytest.mark.edge
def test_suspicious_chrome_without_client_hints(http_client):
    # Chrome UA без sec-ch-ua (+2) и без accept-language (+1) = 3 балла → SUSPICIOUS
    response = http_client.get("/", headers={"user-agent": DESKTOP_CHROME_UA})
    payload = response.json()

    assert payload["verdict"] == "SUSPICIOUS", payload["analysis"]["reasons"]
    assert payload["blocked"] is False
    assert 2 <= payload["analysis"]["bot_score"] < 5


@pytest.mark.edge
def test_rate_limit_high_frequency(http_client):
    # Уникальный IP чтобы не смешиваться со счётчиком других тестов
    headers = {
        "user-agent": DESKTOP_CHROME_UA,
        "x-forwarded-for": "203.0.113.42",
    }

    last_payload = None
    for _ in range(35):
        response = http_client.get("/", headers=headers)
        last_payload = response.json()

    analysis = last_payload["analysis"]
    assert analysis["request_count_last_minute"] >= 31
    assert any("High request frequency" in r for r in analysis["reasons"])
    assert last_payload["verdict"] == "BOT", analysis["reasons"]
