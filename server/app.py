# app.py
from flask import Flask, jsonify, request
from waitress import serve
import json
from src.white_list import white_list, save_white_list, add_to_white_list, remove_from_white_list
from src.black_list import black_list, save_black_list, add_to_black_list, remove_from_black_list
from src.utils import is_valid_url_regex, extract_full_domain, extract_base_domain
from functools import lru_cache
from src.ai.url import detector as url_analyzer
from warnings import filterwarnings

filterwarnings('ignore')


app = Flask(__name__)

@app.route('/api/v1/blacklist', methods=['POST'])
def add_blacklist():
    try:
        data = request.get_json()
        if not data or 'link' not in data:
            return jsonify({"error": "Link is required"}), 400
        link = data['link']
        add_to_black_list(link)
        save_black_list(black_list)
        if link in white_list:
            remove_from_white_list(link)
            save_white_list(white_list)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify(black_list)

@app.route('/api/v1/whitelist', methods=['POST'])
def add_whitelist():
    try:
        data = request.get_json()
        if not data or 'link' not in data:
            return jsonify({"error": "Link is required"}), 400
        link = data['link']
        add_to_white_list(link)
        save_white_list(white_list)
        if link in black_list:
            remove_from_black_list(link)
            save_black_list(black_list)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/whitelist', methods=['GET'])
def get_whitelist():
    print('whitelist')
    return jsonify(white_list)

@lru_cache(8192)
@app.route('/api/v1/fast', methods=['POST'])
def check_fast():
    try:
        data = request.get_json()
        if not data or 'link' not in data:
            return jsonify({"error": "Link is required"}), 400
        link = data['link']
        if is_valid_url_regex(link):
            base_domain = extract_base_domain(link)
            full_domain = extract_full_domain(link)
            if base_domain in white_list:
                if full_domain in white_list:
                    return {'phishing': False, 'source': 'whitelist'}
                else:
                    if full_domain in black_list:
                        return {'phishing': True, 'source': 'blacklist'}
                    else:
                        return {'phishing': None}
            else:
                if base_domain in black_list or full_domain in black_list:
                    return {'phishing': True, 'source': 'blacklist'}
                else:
                    return {'phishing': None}
        else:
            return jsonify({"error": "Link is not correct"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@lru_cache(8192)
@app.route('/api/v1/ai', methods=['POST'])
def check_url_ai():
    try:
        data = request.get_json()
        if not data or 'link' not in data:
            return jsonify({"error": "Link is required"}), 400
        link = data['link']
        if is_valid_url_regex(link):
            base_domain = extract_base_domain(link)
            full_domain = extract_full_domain(link)
            if base_domain in white_list:
                if full_domain in white_list:
                    return {'phishing': False, 'source': 'whitelist'}
                else:
                    if full_domain in black_list:
                        return {'phishing': True, 'source': 'blacklist'}
                    else:
                        res = url_analyzer.predict(link)
                        phishing_chance = round(res['phishing_probability']*res['confidence'], 4)
                        if phishing_chance > 0.65:
                            return {'phishing': True, 'source': 'ai_url', 'chance': phishing_chance}
                        return {'phishing': False, 'source': 'ai_url', 'chance': phishing_chance}

            else:
                if base_domain in black_list or full_domain in black_list:
                    return {'phishing': True, 'source': 'blacklist'}
                else:
                    res = url_analyzer.predict(link)
                    phishing_chance = round(res['phishing_probability']*res['confidence'], 4)
                    if phishing_chance > 0.65:
                        return {'phishing': True, 'source': 'ai_url', 'chance': phishing_chance}
                    return {'phishing': False, 'source': 'ai_url', 'chance': phishing_chance}
        else:
            return jsonify({"error": "Link is not correct"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@lru_cache(1024)
@app.route('/api/v1/ai-content', methods=['POST'])
def check_ai_content():
    try:
        data = request.get_json()
        if not data or 'link' not in data or 'content' not in data:
            return jsonify({"error": "Link and content is required"}), 400
        link = data['link']
        content = data['content']
        if is_valid_url_regex(link):
            base_domain = extract_base_domain(link)
            full_domain = extract_full_domain(link)
            if base_domain in white_list:
                if full_domain in white_list:
                    return {'phishing': False, 'source': 'whitelist'}
                else:
                    if full_domain in black_list:
                        return {'phishing': True, 'source': 'blacklist'}
                    else:
                        res = url_analyzer.predict(link, content)
                        phishing_chance = round(res['phishing_probability']*res['confidence'], 4)
                        if phishing_chance > 0.65:
                            return {'phishing': True, 'source': 'ai_url', 'chance': phishing_chance}
                        return {'phishing': False, 'source': 'ai_url', 'chance': phishing_chance}

            else:
                if base_domain in black_list or full_domain in black_list:
                    return {'phishing': True, 'source': 'blacklist'}
                else:
                    res = url_analyzer.predict(link, content)
                    phishing_chance = round(res['phishing_probability']*res['confidence'], 4)
                    if phishing_chance > 0.65:
                        return {'phishing': True, 'source': 'ai_url', 'chance': phishing_chance}
                    return {'phishing': False, 'source': 'ai_url', 'chance': phishing_chance}
        else:
            return jsonify({"error": "Link is not correct"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting API server on http://localhost:8787")
    print("Press Ctrl+C to stop")
    serve(app, host='localhost', port=8787)
    #app.run(debug=True, host='localhost', port=8787)