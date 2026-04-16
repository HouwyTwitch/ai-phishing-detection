"""
АнтиФиш — API-сервер обнаружения фишинга.
"""
import logging
import logging.handlers
import time
import os
from collections import defaultdict
from threading import Lock
from warnings import filterwarnings

from flask import Flask, jsonify, request, g
from waitress import serve

from config import Config
from src.white_list import white_list, save_white_list, add_to_white_list, remove_from_white_list
from src.black_list import black_list, save_black_list, add_to_black_list, remove_from_black_list
from src.utils import is_valid_url_regex, extract_full_domain, extract_base_domain
from src.ai.url import detector as url_analyzer

filterwarnings("ignore")

# ── Инициализация ──────────────────────────────────────────────────────────────

Config.ensure_dirs()

# Логирование
log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
file_handler = logging.handlers.RotatingFileHandler(
    Config.LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
file_handler.setFormatter(log_formatter)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
    handlers=[file_handler, stream_handler],
)
logger = logging.getLogger("antiphish")

app = Flask(__name__)

# ── TTL-кэш ──────────────────────────────────────────────────────────────────

class _TTLCache:
    """Потокобезопасный кэш с временем жизни записей."""

    def __init__(self, ttl: int = 600, maxsize: int = 8192) -> None:
        self._store: dict = {}
        self._ttl = ttl
        self._maxsize = maxsize
        self._lock = Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires = entry
            if time.monotonic() < expires:
                return value
            del self._store[key]
            return None

    def set(self, key: str, value) -> None:
        with self._lock:
            if len(self._store) >= self._maxsize:
                # Удаляем 10% самых старых записей
                now = time.monotonic()
                expired = [k for k, (_, exp) in self._store.items() if exp < now]
                for k in expired:
                    del self._store[k]
                if len(self._store) >= self._maxsize:
                    # Удаляем случайные 10%
                    keys = list(self._store.keys())[: self._maxsize // 10]
                    for k in keys:
                        del self._store[k]
            self._store[key] = (value, time.monotonic() + self._ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)


url_cache = _TTLCache(ttl=Config.CACHE_TTL, maxsize=Config.CACHE_MAXSIZE)

# ── Rate-limiter ──────────────────────────────────────────────────────────────

class _RateLimiter:
    """Простой счётчик запросов с окном времени."""

    def __init__(self, max_requests: int = 120, window: int = 60) -> None:
        self._requests: dict = defaultdict(list)
        self._max = max_requests
        self._window = window
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            window_start = now - self._window
            self._requests[key] = [t for t in self._requests[key] if t > window_start]
            if len(self._requests[key]) >= self._max:
                return False
            self._requests[key].append(now)
            return True


rate_limiter = _RateLimiter(
    max_requests=Config.RATE_LIMIT, window=Config.RATE_WINDOW
)

# ── Вспомогательные функции ───────────────────────────────────────────────────

def _origin_is_allowed(origin: str) -> bool:
    """Проверяет, разрешён ли CORS-источник."""
    if not origin:
        return False
    for allowed in Config.CORS_ORIGINS:
        if allowed == "*":
            return True
        # Поддержка wildcard вида chrome-extension://*
        if allowed.endswith("/*"):
            if origin.startswith(allowed[:-1]):
                return True
        elif origin == allowed:
            return True
    return False


def _add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if _origin_is_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        # Разрешаем запросы без Origin (localhost, Postman)
        response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response


@app.after_request
def after_request(response):
    return _add_cors_headers(response)


@app.before_request
def before_request():
    # Preflight-запросы пропускаем без проверок
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # ── Rate limiting ──
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if not rate_limiter.is_allowed(client_ip):
        logger.warning("Rate limit exceeded for %s", client_ip)
        return jsonify({"error": "Слишком много запросов. Повторите позже."}), 429

    # ── API Key ──
    if Config.API_KEY:
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != Config.API_KEY:
            logger.warning("Invalid API key from %s", client_ip)
            return jsonify({"error": "Неверный API-ключ."}), 401

    g.client_ip = client_ip


# ── Вспомогательная логика проверки URL ──────────────────────────────────────

def _check_lists(link: str):
    """
    Проверяет URL по белому/чёрному спискам.
    Возвращает dict-результат или None (не найдено в списках).
    """
    base_domain = extract_base_domain(link)
    full_domain = extract_full_domain(link)

    if base_domain in white_list:
        if full_domain in white_list or full_domain == base_domain:
            return {"phishing": False, "source": "whitelist"}
        if full_domain in black_list:
            return {"phishing": True, "source": "blacklist"}
        return None  # поддомен — нужна AI-проверка

    if base_domain in black_list or full_domain in black_list:
        return {"phishing": True, "source": "blacklist"}

    return None


def _ai_result(link: str, content: str | None, threshold: float) -> dict:
    """Запускает ML-модель и возвращает результат."""
    res = url_analyzer.predict(link, content)
    chance = round(res["phishing_probability"] * res["confidence"], 4)
    return {
        "phishing": chance > threshold,
        "source": "ai_content" if content else "ai_url",
        "chance": chance,
    }


# ── Эндпоинты ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Проверка работоспособности сервера."""
    return jsonify({
        "status": "ok",
        "version": "1.1.0",
        "model_loaded": url_analyzer.model is not None,
        "blacklist_size": len(black_list),
        "whitelist_size": len(white_list),
        "cache_size": len(url_cache._store),
        "timestamp": int(time.time()),
    })


@app.route("/api/v1/fast", methods=["POST", "OPTIONS"])
def check_fast():
    """Быстрая проверка по белому/чёрному спискам."""
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        if not is_valid_url_regex(link):
            return jsonify({"error": "Некорректный URL."}), 400

        cached = url_cache.get(f"fast:{link}")
        if cached is not None:
            return jsonify({**cached, "cached": True})

        result = _check_lists(link)
        if result is None:
            result = {"phishing": None}

        url_cache.set(f"fast:{link}", result)
        logger.debug("FAST %s → %s", link, result)
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /fast: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/ai", methods=["POST", "OPTIONS"])
def check_url_ai():
    """AI-анализ URL без контента страницы."""
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        threshold = float(data.get("threshold", Config.PHISHING_THRESHOLD))
        threshold = max(0.0, min(1.0, threshold))

        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        if not is_valid_url_regex(link):
            return jsonify({"error": "Некорректный URL."}), 400

        cache_key = f"ai:{link}:{threshold:.2f}"
        cached = url_cache.get(cache_key)
        if cached is not None:
            return jsonify({**cached, "cached": True})

        list_result = _check_lists(link)
        if list_result is not None:
            url_cache.set(cache_key, list_result)
            return jsonify(list_result)

        result = _ai_result(link, None, threshold)
        url_cache.set(cache_key, result)
        logger.info("AI %s → chance=%.4f phishing=%s", link, result["chance"], result["phishing"])
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /ai: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/ai-content", methods=["POST", "OPTIONS"])
def check_ai_content():
    """AI-анализ URL с содержимым страницы (Премиум)."""
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        content = (data.get("content") or "").strip() or None
        threshold = float(data.get("threshold", Config.PHISHING_THRESHOLD))
        threshold = max(0.0, min(1.0, threshold))

        if not link:
            return jsonify({"error": "Поля 'link' и 'content' обязательны."}), 400
        if not is_valid_url_regex(link):
            return jsonify({"error": "Некорректный URL."}), 400

        cache_key = f"ai-content:{link}:{threshold:.2f}"
        cached = url_cache.get(cache_key)
        if cached is not None:
            return jsonify({**cached, "cached": True})

        list_result = _check_lists(link)
        if list_result is not None:
            url_cache.set(cache_key, list_result)
            return jsonify(list_result)

        result = _ai_result(link, content, threshold)
        url_cache.set(cache_key, result)
        logger.info(
            "AI-CONTENT %s → chance=%.4f phishing=%s",
            link, result["chance"], result["phishing"],
        )
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /ai-content: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/blacklist", methods=["GET", "POST", "OPTIONS"])
def manage_blacklist():
    if request.method == "GET":
        return jsonify(sorted(black_list))
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        add_to_black_list(link)
        save_black_list(black_list)
        if link in white_list:
            remove_from_white_list(link)
            save_white_list(white_list)
        url_cache.delete(f"fast:{link}")
        url_cache.delete(f"ai:{link}")
        url_cache.delete(f"ai-content:{link}")
        logger.info("Добавлен в чёрный список: %s", link)
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Ошибка /blacklist POST: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/whitelist", methods=["GET", "POST", "OPTIONS"])
def manage_whitelist():
    if request.method == "GET":
        return jsonify(sorted(white_list))
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        add_to_white_list(link)
        save_white_list(white_list)
        if link in black_list:
            remove_from_black_list(link)
            save_black_list(black_list)
        url_cache.delete(f"fast:{link}")
        url_cache.delete(f"ai:{link}")
        url_cache.delete(f"ai-content:{link}")
        logger.info("Добавлен в белый список: %s", link)
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Ошибка /whitelist POST: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── Запуск ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("АнтиФиш API v1.1.0 запущен на http://%s:%s", Config.HOST, Config.PORT)
    logger.info("Чёрный список: %d доменов | Белый список: %d доменов",
                len(black_list), len(white_list))
    if Config.API_KEY:
        logger.info("Авторизация через X-API-Key: включена")
    else:
        logger.warning("API-ключ не задан — авторизация отключена (режим разработки)")
    serve(app, host=Config.HOST, port=Config.PORT, threads=8)
