import logging
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import tldextract
from bs4 import BeautifulSoup
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("antiphish.ml")

_BASE = Path(__file__).parent.parent.parent  # server/
_KEYWORDS_PATH = _BASE / "assets" / "phishing_keywords.txt"

try:
    phishing_terms = _KEYWORDS_PATH.read_text(encoding="utf-8-sig").splitlines()
    phishing_terms = [t.strip().lower() for t in phishing_terms if t.strip()]
except Exception as exc:
    logger.warning("Не удалось загрузить ключевые слова фишинга: %s", exc)
    phishing_terms = []


class PhishingDetector:
    def __init__(self) -> None:
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names: list = []

    # ── Извлечение признаков ───────────────────────────────────────────────

    def extract_url_features(self, url: str) -> dict:
        features = {}
        try:
            features["length_url"] = len(url)
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            features["length_hostname"] = len(hostname)

            ext = tldextract.extract(url)
            domain = ext.domain
            suffix = ext.suffix
            subdomain = ext.subdomain

            features["ip"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname) else 0
            features["nb_dots"] = url.count(".")
            features["nb_hyphens"] = url.count("-")
            features["nb_at"] = url.count("@")
            features["nb_qm"] = url.count("?")
            features["nb_and"] = url.count("&")
            features["nb_eq"] = url.count("=")
            features["nb_underscore"] = url.count("_")
            features["nb_slash"] = url.count("/")
            features["nb_colon"] = url.count(":")
            features["nb_www"] = 1 if "www" in hostname.lower() else 0
            features["nb_com"] = 1 if ".com" in hostname.lower() else 0
            features["http_in_path"] = 1 if "http" in (parsed.path or "") else 0
            features["https_token"] = 1 if parsed.scheme == "https" else 0

            digits_url = sum(c.isdigit() for c in url)
            digits_host = sum(c.isdigit() for c in hostname)
            features["ratio_digits_url"] = digits_url / len(url) if url else 0
            features["ratio_digits_host"] = digits_host / len(hostname) if hostname else 0

            features["punycode"] = 1 if "xn--" in hostname else 0
            features["port"] = 1 if parsed.port is not None else 0
            features["tld_in_path"] = 1 if suffix and suffix in (parsed.path or "") else 0
            features["tld_in_subdomain"] = 1 if suffix and suffix in subdomain else 0
            features["nb_subdomains"] = len([s for s in subdomain.split(".") if s]) if subdomain else 0
            features["prefix_suffix"] = 1 if "-" in domain else 0

            shorteners = {
                "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
                "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "shorte.st",
                "adf.ly", "bc.vc",
            }
            features["shortening_service"] = 1 if any(s in hostname for s in shorteners) else 0

            extensions = {".exe", ".zip", ".rar", ".js", ".css", ".php", ".html", ".scr"}
            features["path_extension"] = 1 if any((parsed.path or "").endswith(e) for e in extensions) else 0
            features["phish_hints"] = sum(1 for term in phishing_terms if term in url.lower())
            features["random_domain"] = 1 if len(domain) > 10 and sum(c.isdigit() for c in domain) > 3 else 0

        except Exception as exc:
            logger.debug("Ошибка извлечения URL-признаков: %s", exc)
            features = {k: 0 for k in self.get_default_features()}
        return features

    def extract_content_features(self, url: str, html_content: str | None = None) -> dict:
        features = {
            "nb_extCSS": 0,
            "login_form": 0,
            "external_favicon": 0,
            "iframe": 0,
            "popup_window": 0,
            "links_in_tags": 0,
        }
        if not html_content:
            return features
        try:
            soup = BeautifulSoup(html_content, "lxml")
            ext_css = soup.find_all("link", {"rel": "stylesheet", "href": True})
            features["nb_extCSS"] = len(
                [c for c in ext_css if self._is_external(c["href"], url)]
            )
            features["login_form"] = 1 if soup.find("form") else 0
            favicons = soup.find_all("link", rel=lambda r: r and any(v in r for v in ("icon", "shortcut icon")))
            features["external_favicon"] = 1 if any(
                self._is_external(f.get("href", ""), url) for f in favicons
            ) else 0
            features["iframe"] = 1 if soup.find("iframe") else 0
            popup_tokens = {"window.open", "alert(", "confirm(", "prompt("}
            features["popup_window"] = 1 if any(
                tok in (script.string or "") for script in soup.find_all("script")
                for tok in popup_tokens
            ) else 0
            features["links_in_tags"] = (
                len(soup.find_all(["a", "link"], href=True))
                + len(soup.find_all(["img", "script"], src=True))
            )
        except Exception as exc:
            logger.debug("Ошибка извлечения признаков контента: %s", exc)
        return features

    def extract_whois_features(self, url: str) -> dict:
        features = {"domain_age": 0, "dns_record": 0}
        try:
            import whois
            domain = tldextract.extract(url).registered_domain
            if not domain:
                return features
            info = whois.whois(domain)
            features["dns_record"] = 1 if info else 0
            creation = info.creation_date
            if creation:
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    features["domain_age"] = max(0, (datetime.now() - creation).days)
        except Exception:
            pass
        return features

    def _is_external(self, href: str, base_url: str) -> bool:
        try:
            return (
                tldextract.extract(href).registered_domain
                != tldextract.extract(base_url).registered_domain
            )
        except Exception:
            return False

    def get_default_features(self) -> dict:
        return {
            "length_url": 0, "length_hostname": 0, "ip": 0, "nb_dots": 0,
            "nb_hyphens": 0, "nb_at": 0, "nb_qm": 0, "nb_and": 0, "nb_eq": 0,
            "nb_underscore": 0, "nb_slash": 0, "nb_colon": 0, "nb_www": 0,
            "nb_com": 0, "http_in_path": 0, "https_token": 0, "ratio_digits_url": 0,
            "ratio_digits_host": 0, "punycode": 0, "port": 0, "tld_in_path": 0,
            "tld_in_subdomain": 0, "nb_subdomains": 0, "prefix_suffix": 0,
            "shortening_service": 0, "path_extension": 0, "phish_hints": 0,
            "random_domain": 0, "nb_extCSS": 0, "login_form": 0,
            "external_favicon": 0, "iframe": 0, "popup_window": 0,
            "links_in_tags": 0, "domain_age": 0, "dns_record": 0,
        }

    def extract_all_features(self, url: str, html_content: str | None = None) -> dict:
        features = {}
        features.update(self.extract_url_features(url))
        features.update(self.extract_whois_features(url))
        features.update(
            self.extract_content_features(url, html_content)
            if html_content
            else {
                "nb_extCSS": 0, "login_form": 0, "external_favicon": 0,
                "iframe": 0, "popup_window": 0, "links_in_tags": 0,
            }
        )
        return features

    # ── Предсказание ──────────────────────────────────────────────────────

    def predict(self, url: str, html_content: str | None = None) -> dict:
        if self.model is None:
            raise RuntimeError("Модель не загружена. Вызовите load_model().")

        features = self.extract_all_features(url, html_content)
        vector = [features.get(f, 0) for f in self.feature_names]
        scaled = self.scaler.transform([vector])
        prediction = self.model.predict(scaled)[0]
        proba = self.model.predict_proba(scaled)[0]

        return {
            "url": url,
            "is_phishing": bool(prediction),
            "phishing_probability": float(proba[1]) if len(proba) > 1 else float(proba[0]),
            "confidence": float(max(proba)),
            "features_used": sum(1 for v in vector if v != 0),
            "total_features": len(self.feature_names),
        }

    def load_model(self, model_path: str | Path) -> None:
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Файл модели не найден: {path}")
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        logger.info("Модель загружена: %s (%d признаков)", path.name, len(self.feature_names))


# ── Глобальный экземпляр ───────────────────────────────────────────────────────

detector = PhishingDetector()
_model_path = _BASE / "assets" / "phishing_detector.pkl"
detector.load_model(_model_path)
