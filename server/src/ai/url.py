import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import urllib.parse
import tldextract
import re
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import time


phishing_terms = open('assets/phishing_domains.txt').read().splitlines()

                            
class PhishingDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        
    def extract_url_features(self, url):
        """Извлечение признаков из URL"""
        features = {}
        
        try:
            # Базовые характеристики URL
            features['length_url'] = len(url)
            
            # Парсинг URL
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ''
            features['length_hostname'] = len(hostname)
            
            # Извлечение домена
            ext = tldextract.extract(url)
            domain = ext.domain
            suffix = ext.suffix
            subdomain = ext.subdomain
            
            # IP адрес
            features['ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0
            
            # Количество различных символов
            features['nb_dots'] = url.count('.')
            features['nb_hyphens'] = url.count('-')
            features['nb_at'] = url.count('@')
            features['nb_qm'] = url.count('?')
            features['nb_and'] = url.count('&')
            features['nb_eq'] = url.count('=')
            features['nb_underscore'] = url.count('_')
            features['nb_slash'] = url.count('/')
            features['nb_colon'] = url.count(':')
            
            # Ключевые слова
            features['nb_www'] = 1 if 'www' in hostname.lower() else 0
            features['nb_com'] = 1 if '.com' in hostname.lower() else 0
            
            # HTTP/HTTPS
            features['http_in_path'] = 1 if 'http' in (parsed.path or '') else 0
            features['https_token'] = 1 if parsed.scheme == 'https' else 0
            
            # Цифры
            digits_url = sum(c.isdigit() for c in url)
            digits_host = sum(c.isdigit() for c in hostname)
            features['ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
            features['ratio_digits_host'] = digits_host / len(hostname) if len(hostname) > 0 else 0
            
            # Punycode
            features['punycode'] = 1 if 'xn--' in hostname else 0
            
            # Порт
            features['port'] = 1 if parsed.port is not None else 0
            
            # TLD в пути и поддомене
            features['tld_in_path'] = 1 if suffix and suffix in (parsed.path or '') else 0
            features['tld_in_subdomain'] = 1 if suffix and suffix in subdomain else 0
            
            # Количество поддоменов
            features['nb_subdomains'] = len([s for s in subdomain.split('.') if s]) if subdomain else 0
            
            # Дефис в домене
            features['prefix_suffix'] = 1 if '-' in domain else 0
            
            # Сервисы сокращения ссылок
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 
                         'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'shorte.st',
                         'adf.ly', 'bc.vc', 'pub.vitrue.com']
            features['shortening_service'] = 1 if any(short in hostname for short in shorteners) else 0
            
            # Расширение в пути
            extensions = ['.exe', '.zip', '.rar', '.js', '.css', '.php', '.html', '.scr']
            features['path_extension'] = 1 if any((parsed.path or '').endswith(ext) for ext in extensions) else 0
            
            # Ключевые слова фишинга
            features['phish_hints'] = sum(1 for term in phishing_terms if term in url.lower())
            
            # Случайность домена
            features['random_domain'] = 1 if len(domain) > 10 and sum(c.isdigit() for c in domain) > 3 else 0
            
        except Exception as e:
            print(f"Error extracting URL features: {e}")
            # Устанавливаем значения по умолчанию
            for key in self.get_default_features().keys():
                features[key] = 0
        
        return features
    
    def extract_content_features(self, url, html_content=None):
        """Извлечение признаков из содержимого страницы"""
        features = {}
        
        try:
            if html_content:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Количество внешних CSS
                external_css = soup.find_all('link', {'rel': 'stylesheet', 'href': True})
                features['nb_extCSS'] = len([css for css in external_css if self.is_external_url(css['href'], url)])
                
                # Наличие форм
                login_forms = soup.find_all('form')
                features['login_form'] = 1 if login_forms else 0
                
                # Внешние фавиконки
                favicons = soup.find_all('link', {'rel': ['icon', 'shortcut icon']})
                features['external_favicon'] = 1 if any(self.is_external_url(favicon.get('href', ''), url) for favicon in favicons) else 0
                
                # IFrame
                features['iframe'] = 1 if soup.find('iframe') else 0
                
                # Popup window (определяем по JavaScript)
                scripts = soup.find_all('script')
                popup_indicators = ['window.open', 'alert(', 'confirm(', 'prompt(']
                features['popup_window'] = 1 if any(indicator in script.text for script in scripts for indicator in popup_indicators) else 0
                
                # Ссылки в тегах
                links_in_tags = len(soup.find_all(['a', 'link', 'script', 'img'], href=True)) + \
                               len(soup.find_all(['img', 'script'], src=True))
                features['links_in_tags'] = links_in_tags
                
            else:
                # Если контент не предоставлен, устанавливаем значения по умолчанию
                features.update({
                    'nb_extCSS': 0,
                    'login_form': 0,
                    'external_favicon': 0,
                    'iframe': 0,
                    'popup_window': 0,
                    'links_in_tags': 0
                })
                
        except Exception as e:
            print(f"Error extracting content features: {e}")
            features.update({
                'nb_extCSS': 0,
                'login_form': 0,
                'external_favicon': 0,
                'iframe': 0,
                'popup_window': 0,
                'links_in_tags': 0
            })
        
        return features
    
    def extract_whois_features(self, url):
        """Извлечение WHOIS признаков (быстрых)"""
        features = {}
        
        try:
            domain = tldextract.extract(url).registered_domain
            if domain:
                whois_info = whois.whois(domain)
                
                # Возраст домена (в днях)
                if whois_info.creation_date:
                    if isinstance(whois_info.creation_date, list):
                        creation_date = whois_info.creation_date[0]
                    else:
                        creation_date = whois_info.creation_date
                    
                    if creation_date:
                        domain_age = (datetime.now() - creation_date).days
                        features['domain_age'] = domain_age
                    else:
                        features['domain_age'] = 0
                else:
                    features['domain_age'] = 0
                    
                # DNS запись
                features['dns_record'] = 1 if whois_info else 0
                
            else:
                features['domain_age'] = 0
                features['dns_record'] = 0
                
        except Exception:
            features['domain_age'] = 0
            features['dns_record'] = 0
        
        return features
    
    def is_external_url(self, href, base_url):
        """Проверка, является ли ссылка внешней"""
        try:
            base_domain = tldextract.extract(base_url).registered_domain
            href_domain = tldextract.extract(href).registered_domain
            return href_domain and href_domain != base_domain
        except:
            return False
    
    def get_default_features(self):
        """Возвращает признаки по умолчанию"""
        return {
            'length_url': 0, 'length_hostname': 0, 'ip': 0, 'nb_dots': 0,
            'nb_hyphens': 0, 'nb_at': 0, 'nb_qm': 0, 'nb_and': 0, 'nb_eq': 0,
            'nb_underscore': 0, 'nb_slash': 0, 'nb_colon': 0, 'nb_www': 0,
            'nb_com': 0, 'http_in_path': 0, 'https_token': 0, 'ratio_digits_url': 0,
            'ratio_digits_host': 0, 'punycode': 0, 'port': 0, 'tld_in_path': 0,
            'tld_in_subdomain': 0, 'nb_subdomains': 0, 'prefix_suffix': 0,
            'shortening_service': 0, 'path_extension': 0, 'phish_hints': 0,
            'random_domain': 0, 'nb_extCSS': 0, 'login_form': 0, 'external_favicon': 0,
            'iframe': 0, 'popup_window': 0, 'links_in_tags': 0, 'domain_age': 0,
            'dns_record': 0
        }
    
    def extract_all_features(self, url, html_content=None):
        """Извлечение всех признаков"""
        features = {}
        
        # URL признаки
        url_features = self.extract_url_features(url)
        features.update(url_features)
        
        # WHOIS признаки (быстрые)
        whois_features = self.extract_whois_features(url)
        features.update(whois_features)
        
        # Признаки содержимого (если предоставлено)
        if html_content:
            content_features = self.extract_content_features(url, html_content)
            features.update(content_features)
        else:
            # Устанавливаем значения по умолчанию для контентных признаков
            content_defaults = {
                'nb_extCSS': 0, 'login_form': 0, 'external_favicon': 0,
                'iframe': 0, 'popup_window': 0, 'links_in_tags': 0
            }
            features.update(content_defaults)
        
        return features
    
    def predict(self, url, html_content=None):
        """Предсказание для URL"""
        if self.model is None:
            raise ValueError("Модель не загружена!")
        
        # Извлекаем признаки
        features = self.extract_all_features(url, html_content)
        
        # Создаем вектор признаков в правильном порядке
        feature_vector = [features.get(feature, 0) for feature in self.feature_names]
        
        # Масштабируем и предсказываем
        feature_vector_scaled = self.scaler.transform([feature_vector])
        prediction = self.model.predict(feature_vector_scaled)[0]
        probability = self.model.predict_proba(feature_vector_scaled)[0]
        
        return {
            'url': url,
            'is_phishing': bool(prediction),
            'phishing_probability': float(probability[1]) if len(probability) > 1 else float(probability[0]),
            'confidence': float(max(probability)),
            'features_used': len([f for f in feature_vector if f != 0]),
            'total_features': len(self.feature_names)
        }
    
    def load_model(self, model_path):
        """Загрузка обученной модели"""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            print(f"Модель загружена. Признаки: {len(self.feature_names)}")
        except Exception as e:
            print(f"Ошибка загрузки модели: {e}")
            raise

# Создаем глобальный экземпляр детектора
detector = PhishingDetector()
detector.load_model('assets/phishing_detector.pkl')