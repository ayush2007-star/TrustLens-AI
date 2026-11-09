import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.mark.parametrize(
    "setting,value",
    [
        ("PORT", 0),
        ("PORT", 65536),
        ("REQUEST_TIMEOUT_SECONDS", 0),
        ("MAX_REDIRECTS", 0),
        ("MAX_RESPONSE_BYTES", 0),
        ("MAX_RESPONSE_BYTES", 10_485_761),
    ],
)
def test_invalid_network_settings_are_rejected(setting, value):
    with pytest.raises(ValidationError):
        Settings(**{setting: value})


def test_production_requires_a_long_access_token():
    with pytest.raises(ValidationError):
        Settings(ENVIRONMENT="production")


def test_production_accepts_a_long_access_token():
    configured = Settings(
        ENVIRONMENT="production",
        APP_ACCESS_TOKEN="x" * 32,
    )
    assert configured.APP_ACCESS_TOKEN == "x" * 32


def test_cors_origins_parses_comma_and_json_strings():
    cfg_comma = Settings(CORS_ORIGINS="https://demo.app, https://other.app")
    assert cfg_comma.CORS_ORIGINS == ["https://demo.app", "https://other.app"]

    cfg_json = Settings(CORS_ORIGINS='["https://demo.app", "https://other.app"]')
    assert cfg_json.CORS_ORIGINS == ["https://demo.app", "https://other.app"]

