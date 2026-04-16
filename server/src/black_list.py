import logging
import requests
from pathlib import Path
from threading import Lock

logger = logging.getLogger("antiphish.blacklist")

_BASE = Path(__file__).parent.parent
_path = _BASE / "assets" / "phishing_domains.txt"
_lock = Lock()

_ONLINE_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database"
    "/refs/heads/master/phishing-domains-ACTIVE.txt"
)


def load_offline_black_list() -> list:
    try:
        return _path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as exc:
        logger.warning("Офлайн-чёрный список недоступен: %s", exc)
        return []


def load_online_black_list() -> list:
    try:
        response = requests.get(_ONLINE_URL, timeout=20)
        response.raise_for_status()
        data = response.content.decode("utf-8-sig").splitlines()
        logger.info("Онлайн-чёрный список загружен: %d доменов", len(data))
        return data
    except Exception as exc:
        logger.warning("Онлайн-чёрный список недоступен: %s", exc)
        return []


def get_black_list() -> list:
    offline = load_offline_black_list()
    before = len(offline)
    combined = list(set(offline + load_online_black_list()))
    logger.info(
        "Чёрный список: было %d, стало %d (+%d новых)",
        before, len(combined), max(0, len(combined) - before),
    )
    return combined


def save_black_list(bl: list) -> None:
    try:
        _path.parent.mkdir(parents=True, exist_ok=True)
        _path.write_text("\n".join(bl), encoding="utf-8-sig")
    except Exception as exc:
        logger.error("Не удалось сохранить чёрный список: %s", exc)


def add_to_black_list(item: str) -> None:
    with _lock:
        if item not in black_list:
            black_list.append(item)


def remove_from_black_list(item: str) -> None:
    with _lock:
        try:
            black_list.remove(item)
        except ValueError:
            pass


black_list: list = get_black_list()
save_black_list(black_list)
