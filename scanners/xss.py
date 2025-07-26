import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from datetime import datetime
import os

XSS_PAYLOAD_FILE = "payloads/xss.txt"
HISTORY_DIR = "history"

def chen_payload_vao_url(url, param, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query, keep_blank_values=True)
    if not query:
        return None
    new_query = query.copy()
    new_query[param] = [payload]
    modified_query = urlencode(new_query, doseq=True)
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        modified_query,
        parsed_url.fragment
    ))
    return new_url

def trich_form(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        forms = soup.find_all('form')
        danh_sach_forms = []
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)
            inputs = {}
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                if not name:
                    continue
                inputs[name] = 'test'
            danh_sach_forms.append({
                "url": form_url,
                "method": method,
                "data": inputs
            })
        return danh_sach_forms
    except Exception:
        return []

def scan_xss(target_url, output):
    output.write("======= XSS =======\n")
    output.write(f"[*] Đang kiểm tra XSS trên: {target_url}\n")
    parsed = urlparse(target_url)
    has_params = bool(parse_qs(parsed.query, keep_blank_values=True))
    found_payloads = set()
    # Đọc payloads
    try:
        with open(XSS_PAYLOAD_FILE, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception:
        output.write("[X] Không thể đọc file payloads/xss.txt\n")
        return
    # Nếu có query param, thử từng param với từng payload
    if has_params:
        query = parse_qs(parsed.query, keep_blank_values=True)
        for param in query:
            for payload in payloads:
                test_url = chen_payload_vao_url(target_url, param, payload)
                try:
                    res = requests.get(test_url, timeout=5)
                    if payload in res.text:
                        found_payloads.add(payload)
                except Exception as e:
                    output.write(f"[!] Lỗi khi gửi request: {e}\n")
    else:
        output.write("[!] URL không chứa tham số. Đang thử tìm form để kiểm tra...\n")
        forms = trich_form(target_url)
        if not forms:
            output.write("[X] Không tìm thấy form để kiểm tra.\n")
            output.write("[✓] Không thể thực hiện kiểm tra XSS.\n\n")
            return
        for form in forms:
            input_names = list(form['data'].keys())
            for input_name in input_names:
                for payload in payloads:
                    data_gui = {}
                    for k in input_names:
                        data_gui[k] = payload if k == input_name else form['data'][k]
                    try:
                        if form['method'] == 'post':
                            res = requests.post(form['url'], data=data_gui, timeout=5)
                        else:
                            res = requests.get(form['url'], params=data_gui, timeout=5)
                        if payload in res.text:
                            found_payloads.add(payload)
                    except Exception as e:
                        output.write(f"[!] Lỗi khi gửi request đến form: {e}\n")
    if found_payloads:
        output.write("[!] Có thể bị tấn công XSS với các payloads:\n")
        for p in found_payloads:
            output.write(f"    - {p}\n")
    else:
        output.write("[✓] Không phát hiện lỗ hổng XSS.\n")
    output.write("\n")
