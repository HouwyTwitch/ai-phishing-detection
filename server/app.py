"""
АнтиФиш — API-сервер обнаружения фишинга.
"""
import logging
import logging.handlers
import time
from collections import defaultdict
from threading import Lock
from warnings import filterwarnings

from flask import Flask, jsonify, request, g, render_template
from waitress import serve

from config import Config
from src.white_list import white_list, save_white_list, add_to_white_list, remove_from_white_list
from src.black_list import black_list, save_black_list, add_to_black_list, remove_from_black_list
from src.utils import is_valid_url_regex, extract_full_domain, extract_base_domain
from src.ai.url import detector as url_analyzer
from src.keys import KeysManager

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

# ── Keys manager ──────────────────────────────────────────────────────────────

keys = KeysManager(Config.API_KEYS_PATH, Config.LICENSE_KEYS_PATH)
keys.seed_from_env(Config.API_KEY)

if keys.requires_auth():
    logger.info("Авторизация: включена (%d API-ключей)", len(keys.list_api_keys()))
else:
    logger.warning("API-ключи не заданы — авторизация отключена (режим разработки)")

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
                now = time.monotonic()
                expired = [k for k, (_, exp) in self._store.items() if exp < now]
                for k in expired:
                    del self._store[k]
                if len(self._store) >= self._maxsize:
                    for k in list(self._store.keys())[: self._maxsize // 10]:
                        del self._store[k]
            self._store[key] = (value, time.monotonic() + self._ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)


url_cache = _TTLCache(ttl=Config.CACHE_TTL, maxsize=Config.CACHE_MAXSIZE)

# ── Rate-limiter ──────────────────────────────────────────────────────────────

class _RateLimiter:
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


rate_limiter = _RateLimiter(max_requests=Config.RATE_LIMIT, window=Config.RATE_WINDOW)

# ── CORS ──────────────────────────────────────────────────────────────────────

def _origin_is_allowed(origin: str) -> bool:
    if not origin:
        return False
    for allowed in Config.CORS_ORIGINS:
        if allowed == "*":
            return True
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
        response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response


@app.after_request
def after_request(response):
    return _add_cors_headers(response)

# ── Auth / before_request ─────────────────────────────────────────────────────

# Endpoints accessible with a user-role key
_USER_PATHS = {"/health", "/api/v1/fast", "/api/v1/ai", "/api/v1/ai-content", "/api/v1/license/verify"}
# Endpoints that bypass auth entirely
_PUBLIC_PATHS = {"/admin", "/api/v1/auth-check"}


@app.before_request
def before_request():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    if request.path in _PUBLIC_PATHS:
        return

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if not rate_limiter.is_allowed(client_ip):
        logger.warning("Rate limit exceeded for %s", client_ip)
        return jsonify({"error": "Слишком много запросов. Повторите позже."}), 429

    if not keys.requires_auth():
        g.role = "admin"
        g.client_ip = client_ip
        return

    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not api_key:
        return jsonify({"error": "Требуется API-ключ."}), 401

    role = keys.get_role(api_key)
    if not role:
        logger.warning("Invalid API key from %s", client_ip)
        return jsonify({"error": "Неверный API-ключ."}), 401

    if role == "user" and request.path not in _USER_PATHS:
        return jsonify({"error": "Недостаточно прав."}), 403

    g.role = role
    g.client_ip = client_ip


# ── URL check helpers ─────────────────────────────────────────────────────────

def _check_lists(link: str):
    base_domain = extract_base_domain(link)
    full_domain = extract_full_domain(link)

    if base_domain in white_list:
        if full_domain in white_list or full_domain == base_domain:
            return {"phishing": False, "source": "whitelist"}
        if full_domain in black_list:
            return {"phishing": True, "source": "blacklist"}
        return None

    if base_domain in black_list or full_domain in black_list:
        return {"phishing": True, "source": "blacklist"}

    return None


def _ai_result(link: str, content: str | None, threshold: float) -> dict:
    res = url_analyzer.predict(link, content)
    chance = round(res["phishing_probability"] * res["confidence"], 4)
    return {
        "phishing": chance > threshold,
        "source": "ai_content" if content else "ai_url",
        "chance": chance,
    }


# ── Detection endpoints ───────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
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

        result = _check_lists(link) or {"phishing": None}
        url_cache.set(f"fast:{link}", result)
        logger.debug("FAST %s → %s", link, result)
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /fast: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/ai", methods=["POST", "OPTIONS"])
def check_url_ai():
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        threshold = max(0.0, min(1.0, float(data.get("threshold", Config.PHISHING_THRESHOLD))))

        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        if not is_valid_url_regex(link):
            return jsonify({"error": "Некорректный URL."}), 400

        cache_key = f"ai:{link}:{threshold:.2f}"
        cached = url_cache.get(cache_key)
        if cached is not None:
            return jsonify({**cached, "cached": True})

        result = _check_lists(link)
        if result is None:
            result = _ai_result(link, None, threshold)
        url_cache.set(cache_key, result)
        logger.info("AI %s → chance=%.4f phishing=%s", link, result.get("chance", "n/a"), result["phishing"])
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /ai: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/ai-content", methods=["POST", "OPTIONS"])
def check_ai_content():
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        content = (data.get("content") or "").strip() or None
        threshold = max(0.0, min(1.0, float(data.get("threshold", Config.PHISHING_THRESHOLD))))

        if not link:
            return jsonify({"error": "Поля 'link' и 'content' обязательны."}), 400
        if not is_valid_url_regex(link):
            return jsonify({"error": "Некорректный URL."}), 400

        cache_key = f"ai-content:{link}:{threshold:.2f}"
        cached = url_cache.get(cache_key)
        if cached is not None:
            return jsonify({**cached, "cached": True})

        result = _check_lists(link)
        if result is None:
            result = _ai_result(link, content, threshold)
        url_cache.set(cache_key, result)
        logger.info("AI-CONTENT %s → chance=%.4f phishing=%s", link, result.get("chance", "n/a"), result["phishing"])
        return jsonify(result)
    except Exception as exc:
        logger.exception("Ошибка /ai-content: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── List management endpoints ─────────────────────────────────────────────────

@app.route("/api/v1/blacklist", methods=["GET", "POST", "DELETE", "OPTIONS"])
def manage_blacklist():
    if request.method == "GET":
        return jsonify(sorted(black_list))
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        if request.method == "DELETE":
            remove_from_black_list(link)
            save_black_list(black_list)
        else:
            add_to_black_list(link)
            save_black_list(black_list)
            if link in white_list:
                remove_from_white_list(link)
                save_white_list(white_list)
        for prefix in ("fast", "ai", "ai-content"):
            url_cache.delete(f"{prefix}:{link}")
        logger.info("%s blacklist: %s", "Removed from" if request.method == "DELETE" else "Added to", link)
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Ошибка /blacklist: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/whitelist", methods=["GET", "POST", "DELETE", "OPTIONS"])
def manage_whitelist():
    if request.method == "GET":
        return jsonify(sorted(white_list))
    try:
        data = request.get_json(silent=True) or {}
        link = (data.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Поле 'link' обязательно."}), 400
        if request.method == "DELETE":
            remove_from_white_list(link)
            save_white_list(white_list)
        else:
            add_to_white_list(link)
            save_white_list(white_list)
            if link in black_list:
                remove_from_black_list(link)
                save_black_list(black_list)
        for prefix in ("fast", "ai", "ai-content"):
            url_cache.delete(f"{prefix}:{link}")
        logger.info("%s whitelist: %s", "Removed from" if request.method == "DELETE" else "Added to", link)
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Ошибка /whitelist: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── Cache ─────────────────────────────────────────────────────────────────────

@app.route("/api/v1/cache/clear", methods=["POST", "OPTIONS"])
def clear_cache():
    try:
        with url_cache._lock:
            url_cache._store.clear()
        logger.info("Кэш очищен администратором")
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Ошибка очистки кэша: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── API key management (admin only) ──────────────────────────────────────────

@app.route("/api/v1/keys", methods=["GET", "POST", "DELETE", "OPTIONS"])
def manage_api_keys():
    if request.method == "GET":
        return jsonify(keys.list_api_keys())
    try:
        data = request.get_json(silent=True) or {}
        if request.method == "DELETE":
            key = (data.get("key") or "").strip()
            if not key:
                return jsonify({"error": "Поле 'key' обязательно."}), 400
            if not keys.remove_api_key(key):
                return jsonify({"error": "Ключ не найден."}), 404
            logger.info("API key revoked")
            return jsonify({"success": True})
        role = (data.get("role") or "user").strip()
        if role not in ("admin", "user"):
            return jsonify({"error": "role должен быть 'admin' или 'user'."}), 400
        name = (data.get("name") or "").strip()
        new_key = keys.add_api_key(role, name)
        logger.info("New API key created: role=%s name=%s", role, name)
        return jsonify({"success": True, "key": new_key, "role": role, "name": name})
    except Exception as exc:
        logger.exception("Ошибка /keys: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── License key management (admin only) ──────────────────────────────────────

@app.route("/api/v1/license", methods=["GET", "POST", "DELETE", "OPTIONS"])
def manage_license_keys():
    if request.method == "GET":
        return jsonify(keys.list_license_keys())
    try:
        data = request.get_json(silent=True) or {}
        if request.method == "DELETE":
            key = (data.get("key") or "").strip()
            if not key:
                return jsonify({"error": "Поле 'key' обязательно."}), 400
            if not keys.revoke_license_key(key):
                return jsonify({"error": "Ключ не найден."}), 404
            logger.info("License key revoked: %s", key)
            return jsonify({"success": True})
        plan = (data.get("plan") or "premium").strip()
        expires = (data.get("expires") or "").strip() or None
        note = (data.get("note") or "").strip()
        new_key = keys.add_license_key(plan, expires, note)
        logger.info("License key created: %s plan=%s", new_key, plan)
        return jsonify({"success": True, "key": new_key, "plan": plan, "expires": expires, "note": note})
    except Exception as exc:
        logger.exception("Ошибка /license: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


@app.route("/api/v1/license/verify", methods=["POST", "OPTIONS"])
def verify_license():
    try:
        data = request.get_json(silent=True) or {}
        key = (data.get("key") or "").strip()
        if not key:
            return jsonify({"error": "Поле 'key' обязательно."}), 400
        info = keys.verify_license_key(key)
        if info is None:
            return jsonify({"valid": False}), 200
        return jsonify({"valid": True, "plan": info.get("plan"), "expires": info.get("expires")})
    except Exception as exc:
        logger.exception("Ошибка /license/verify: %s", exc)
        return jsonify({"error": "Внутренняя ошибка сервера."}), 500


# ── Admin panel & meta ────────────────────────────────────────────────────────

@app.route("/api/v1/auth-check", methods=["GET"])
def auth_check():
    return jsonify({"required": keys.requires_auth()})


@app.route("/api/v1/me", methods=["GET"])
def me():
    return jsonify({"role": getattr(g, "role", "admin")})


@app.route("/admin")
def admin_panel():
    return render_template("admin.html")


# ── Запуск ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("АнтиФиш API v1.1.0 запущен на http://%s:%s", Config.HOST, Config.PORT)
    logger.info("Чёрный список: %d доменов | Белый список: %d доменов",
                len(black_list), len(white_list))
    serve(app, host=Config.HOST, port=Config.PORT, threads=8)
