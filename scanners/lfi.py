import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime
import os

LFI_PAYLOAD_FILE = "payloads/lfi.txt"
HISTORY_DIR = "history"

LFI_SIGNS = [
    "root:x:", "[extensions]", "[boot loader]", "[fonts]", "No such file", "failed to open stream",
    "Warning:", "include(", "fopen(", "Permission denied", "is not readable", "in <b>", "on line", "cannot open",
    "HTTP/1.1 500", "root::0:0:", "bash_history", "<title>Warning", "<title>Fatal error"
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

def scan_lfi(target_url, output):
    output.write("======= LFI =======\n")
    output.write(f"[*] Đang kiểm tra LFI trên: {target_url}\n")
    parsed = urlparse(target_url)
    has_params = bool(parse_qs(parsed.query, keep_blank_values=True))
    found = []
    # Đọc payloads
    try:
        with open(LFI_PAYLOAD_FILE, "r", encoding="utf-8") as f:
            payloads = [line.strip().split('#')[0].strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception:
        output.write("[X] Không thể đọc file payloads/lfi.txt\n")
        return
    if has_params:
        query = parse_qs(parsed.query, keep_blank_values=True)
        for param in query:
            for payload in payloads:
                test_url = chen_payload_vao_url(target_url, param, payload)
                try:
                    res = requests.get(test_url, timeout=7, allow_redirects=True)
                    text = res.text[:1000]  # chỉ lấy 1000 ký tự đầu để kiểm tra
                    for sign in LFI_SIGNS:
                        if sign.lower() in text.lower():
                            found.append((param, payload, sign, text[:200]))
                            break
                    # Nếu status code bất thường
                    if res.status_code >= 500:
                        found.append((param, payload, f"Status {res.status_code}", text[:200]))
                except Exception as e:
                    output.write(f"[!] Lỗi khi gửi request: {e}\n")
    if found:
        output.write("[!] Có thể bị tấn công LFI với các payloads:\n")
        for param, payload, sign, preview in found:
            output.write(f"    - Param: {param} | Payload: {payload} | Dấu hiệu: {sign}\n      Phản hồi: {preview}\n")
    else:
        output.write("[✓] Không phát hiện lỗ hổng LFI.\n")
    output.write("\n")
