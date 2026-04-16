import requests
from datetime import datetime
from threading import Lock


api_url = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt'
_path = 'assets/phishing_domains.txt'
_lock = Lock()


def load_offline_black_list():
    try:
        data = open(_path, encoding='utf-8-sig').read().splitlines()
    except:
        data = []
    return data

def load_online_black_list():
    try:
        response = requests.get(api_url, timeout=20)
        data = response.content.decode('utf-8-sig').splitlines()
    except:
        data = []
    return data

def get_black_list():
    black_list = load_offline_black_list()
    before = len(black_list)
    black_list = black_list + load_online_black_list()
    black_list = list(set(black_list))
    after = len(black_list)
    diff = after - before
    print(datetime.now(), 'blacklist updated with', diff, 'new domains')
    return black_list

def save_black_list(black_list):
    try:
        with open(_path, 'w', encoding='utf-8-sig') as f:
            f.write('\n'.join(black_list))
    except:
        pass

def add_to_black_list(item):
    with _lock:
        black_list.append(item)

def remove_from_black_list(item):
    try:
        with _lock:
            black_list.remove(item)
    except:
        pass

black_list = get_black_list()
save_black_list(black_list)