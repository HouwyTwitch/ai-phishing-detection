"""
Конфигурация сервера АнтиФиш.
Все параметры могут быть переопределены через переменные окружения.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent

load_dotenv(BASE_DIR / ".env")


class Config:
    # ── Сетевые настройки ──────────────────────────────────────────────────
    HOST: str = os.getenv("ANTIPHISH_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("ANTIPHISH_PORT", "8787"))
    DEBUG: bool = os.getenv("ANTIPHISH_DEBUG", "false").lower() == "true"

    # ── Безопасность ───────────────────────────────────────────────────────
    # Пустая строка — авторизация отключена (режим разработки)
    API_KEY: str = os.getenv("ANTIPHISH_API_KEY", "")
    # Разрешённые источники CORS (через запятую)
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv(
            "ANTIPHISH_CORS_ORIGINS",
            "chrome-extension://*,moz-extension://*,http://localhost:*",
        ).split(",")
        if o.strip()
    ]

    # ── Кэш ────────────────────────────────────────────────────────────────
    CACHE_TTL: int = int(os.getenv("ANTIPHISH_CACHE_TTL", "600"))  # секунды
    CACHE_MAXSIZE: int = int(os.getenv("ANTIPHISH_CACHE_MAXSIZE", "8192"))

    # ── Ограничение запросов ───────────────────────────────────────────────
    RATE_LIMIT: int = int(os.getenv("ANTIPHISH_RATE_LIMIT", "120"))  # запросов/мин
    RATE_WINDOW: int = 60  # секунды

    # ── ML-модель ──────────────────────────────────────────────────────────
    PHISHING_THRESHOLD: float = float(
        os.getenv("ANTIPHISH_THRESHOLD", "0.65")
    )

    # ── Пути ───────────────────────────────────────────────────────────────
    ASSETS_DIR: Path = BASE_DIR / "assets"
    MODEL_PATH: Path = ASSETS_DIR / "phishing_detector.pkl"
    BLACKLIST_PATH: Path = ASSETS_DIR / "phishing_domains.txt"
    WHITELIST_PATH: Path = ASSETS_DIR / "trusted_websites.txt"
    KEYWORDS_PATH: Path = ASSETS_DIR / "phishing_keywords.txt"
    API_KEYS_PATH: Path = ASSETS_DIR / "api_keys.json"
    LICENSE_KEYS_PATH: Path = ASSETS_DIR / "license_keys.json"
    LOG_DIR: Path = BASE_DIR / "logs"

    # ── Логирование ────────────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("ANTIPHISH_LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv(
        "ANTIPHISH_LOG_FILE", str(LOG_DIR / "antiphish.log")
    )

    @classmethod
    def ensure_dirs(cls) -> None:
        """Создаёт необходимые директории при запуске."""
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cls.ASSETS_DIR.mkdir(parents=True, exist_ok=True)
