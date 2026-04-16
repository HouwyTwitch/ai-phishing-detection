import logging
from pathlib import Path
from threading import Lock

logger = logging.getLogger("antiphish.whitelist")

_BASE = Path(__file__).parent.parent
_path = _BASE / "assets" / "trusted_websites.txt"
_lock = Lock()


def load_white_list() -> list:
    try:
        data = _path.read_text(encoding="utf-8-sig").splitlines()
        logger.info("Белый список загружен: %d доменов", len(data))
        return data
    except Exception as exc:
        logger.warning("Белый список недоступен: %s", exc)
        return []


def save_white_list(wl: list) -> None:
    try:
        _path.parent.mkdir(parents=True, exist_ok=True)
        _path.write_text("\n".join(wl), encoding="utf-8-sig")
    except Exception as exc:
        logger.error("Не удалось сохранить белый список: %s", exc)


def add_to_white_list(item: str) -> None:
    with _lock:
        if item not in white_list:
            white_list.append(item)


def remove_from_white_list(item: str) -> None:
    with _lock:
        try:
            white_list.remove(item)
        except ValueError:
            pass


white_list: list = load_white_list()
