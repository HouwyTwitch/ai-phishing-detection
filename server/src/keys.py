import json
import secrets
from datetime import date
from pathlib import Path
from threading import Lock

_lock = Lock()


class KeysManager:
    def __init__(self, api_path: Path, lic_path: Path):
        self._api_path = api_path
        self._lic_path = lic_path
        self._api: dict = {}
        self._lic: dict = {}
        self._load()

    def _load(self):
        for path, attr in [(self._api_path, "_api"), (self._lic_path, "_lic")]:
            if path.exists():
                try:
                    setattr(self, attr, json.loads(path.read_text(encoding="utf-8")))
                except Exception:
                    pass

    def _save(self, which: str):
        if which == "api":
            self._api_path.parent.mkdir(parents=True, exist_ok=True)
            self._api_path.write_text(
                json.dumps(self._api, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        else:
            self._lic_path.parent.mkdir(parents=True, exist_ok=True)
            self._lic_path.write_text(
                json.dumps(self._lic, indent=2, ensure_ascii=False), encoding="utf-8"
            )

    # ── Auth ──────────────────────────────────────────────────────────────────

    def requires_auth(self) -> bool:
        return bool(self._api)

    def get_role(self, key: str) -> str | None:
        entry = self._api.get(key)
        return entry.get("role") if entry else None

    # ── API keys ──────────────────────────────────────────────────────────────

    def list_api_keys(self) -> list:
        return [{"key": k, **v} for k, v in self._api.items()]

    def add_api_key(self, role: str, name: str = "", key: str | None = None) -> str:
        if not key:
            key = secrets.token_hex(24)
        with _lock:
            self._api[key] = {
                "role": role,
                "name": name,
                "created": date.today().isoformat(),
            }
            self._save("api")
        return key

    def remove_api_key(self, key: str) -> bool:
        with _lock:
            if key not in self._api:
                return False
            del self._api[key]
            self._save("api")
        return True

    def seed_from_env(self, env_key: str) -> None:
        """Migrate ANTIPHISH_API_KEY env var into the store on first boot."""
        if env_key and not self._api:
            self.add_api_key("admin", "Default admin (migrated from env)", env_key)

    # ── License keys ──────────────────────────────────────────────────────────

    def list_license_keys(self) -> list:
        return [{"key": k, **v} for k, v in self._lic.items()]

    def _gen_lic_key(self) -> str:
        parts = [secrets.token_hex(2).upper() for _ in range(3)]
        return "APF-" + "-".join(parts)

    def add_license_key(
        self, plan: str = "premium", expires: str | None = None, note: str = ""
    ) -> str:
        key = self._gen_lic_key()
        while key in self._lic:
            key = self._gen_lic_key()
        with _lock:
            self._lic[key] = {
                "plan": plan,
                "expires": expires or None,
                "note": note,
                "created": date.today().isoformat(),
                "active": True,
            }
            self._save("lic")
        return key

    def revoke_license_key(self, key: str) -> bool:
        with _lock:
            if key not in self._lic:
                return False
            del self._lic[key]
            self._save("lic")
        return True

    def verify_license_key(self, key: str) -> dict | None:
        """Returns license info dict or None if invalid/expired/inactive."""
        entry = self._lic.get(key)
        if not entry or not entry.get("active"):
            return None
        if entry.get("expires") and date.today().isoformat() > entry["expires"]:
            return None
        return entry
