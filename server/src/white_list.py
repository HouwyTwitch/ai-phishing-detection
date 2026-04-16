from datetime import datetime
from threading import Lock


_path = 'assets/trusted_websites.txt'
_lock = Lock()


def load_white_list():
    try:
        with open(_path, encoding='utf-8-sig') as f:
            return f.read().splitlines()
    except:
        return []

def save_white_list(white_list):
    try:
        with open(_path, 'w', encoding='utf-8-sig') as f:
            f.write('\n'.join(white_list))
    except:
        pass

def add_to_white_list(item):
    with _lock:
        white_list.append(item)

def remove_from_white_list(item):
    try:
        with _lock:
            white_list.remove(item)
    except:
        pass

white_list = load_white_list()
print(datetime.now(), 'whitelist loaded with', len(white_list), 'domains')