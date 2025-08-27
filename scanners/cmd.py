import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

CMDI_PAYLOAD_FILE = "payloads/cmdi.txt"

CMDI_SIGNS = [
    # Linux/Unix
    "uid=", "gid=", "root:x:", "www-data", "/bin/bash", "/bin/sh", "/bin/ash", "/bin/dash", "/bin/zsh", "/bin/csh", "/bin/tcsh", "/bin/ksh", "/bin/fish", "/bin/", "/usr/", "root@", "total ", "drwx", "-rw-", "bash: ", "Linux",
    # Windows
    "Windows", "Microsoft", "C:\\", "D:\\", "system32", "nt authority", "cmd.exe", "C:/", "D:/", "Volume in drive", "Directory of"
]

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
                input_type = input_tag.get('type', 'text').lower()
                if input_type == 'checkbox':
                    if input_tag.has_attr('checked') or input_tag.get('value'):
                        inputs[name] = input_tag.get('value', 'on')
                else:
                    inputs[name] = input_tag.get('value', 'test')
            for select_tag in form.find_all('select'):
                name = select_tag.get('name')
                if not name:
                    continue
                option = select_tag.find('option')
                if option and option.get('value'):
                    inputs[name] = option.get('value')
                else:
                    inputs[name] = '1'
            danh_sach_forms.append({
                "url": form_url,
                "method": method,
                "data": inputs
            })
        return danh_sach_forms
    except Exception:
        return []

def scan_cmdi(target_url, output):
    output.write("======= CMDi =======\n")
    output.write(f"[*] Đang kiểm tra Command Injection trên: {target_url}\n")
    parsed = urlparse(target_url)
    has_params = bool(parse_qs(parsed.query, keep_blank_values=True))
    found_payloads = set()
    # Đọc payloads
    try:
        with open(CMDI_PAYLOAD_FILE, "r", encoding="utf-8") as f:
            payloads = [line.strip().split('#')[0].strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception:
        output.write("[X] Không thể đọc file payloads/cmdi.txt\n")
        return
    # Chỉ coi là CMDi khi có output thực thi lệnh hệ thống thực sự (không chứa từ khóa lỗi, không chứa từ khóa generic như 'user', 'group', 'home')
    def is_true_cmdi(text):
        for sign in CMDI_SIGNS:
            if sign.lower() in text.lower():
                return True
        return False
    if has_params:
        query = parse_qs(parsed.query, keep_blank_values=True)
        for param in query:
            for payload in payloads:
                test_url = chen_payload_vao_url(target_url, param, payload)
                try:
                    res = requests.get(test_url, timeout=7, allow_redirects=True)
                    text = res.text[:2000]
                    if is_true_cmdi(text):
                        found_payloads.add(payload)
                except Exception as e:
                    output.write(f"[!] Lỗi khi gửi request: {e}\n")
    forms = trich_form(target_url)
    for form in forms:
        input_names = list(form['data'].keys())
        for payload in payloads:
            for input_name in input_names:
                data_gui = {}
                for k in input_names:
                    if k == input_name:
                        data_gui[k] = form['data'][k] + payload
                    else:
                        data_gui[k] = form['data'][k]
                try:
                    if form['method'] == 'post':
                        res = requests.post(form['url'], data=data_gui, timeout=7)
                    else:
                        res = requests.get(form['url'], params=data_gui, timeout=7)
                    text = res.text[:2000]
                    if is_true_cmdi(text):
                        found_payloads.add(payload)
                except Exception as e:
                    output.write(f"[!] Lỗi khi gửi request đến form: {e}\n")
    if found_payloads:
        output.write("[!] Có thể bị tấn công CMDi với các payloads:\n")
        for payload in sorted(found_payloads):
            output.write(f"    - {payload}\n")
    else:
        output.write("[✓] Không phát hiện lỗ hổng CMDi.\n")
    output.write("\n")
