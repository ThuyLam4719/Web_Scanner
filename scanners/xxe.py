import requests
from urllib.parse import urlparse

XXE_PAYLOAD_FILE = "payloads/xxe.txt"

XXE_SIGNS = [
    "root:x:", "<?xml", "<!ENTITY", "<!DOCTYPE", "SYSTEM", "file:///etc/passwd", "c:windows", "root::0:0:", "<user>", "<data>", "<config>"
]

def scan_xxe(target_url, output):
    output.write("======= XXE =======\n")
    output.write(f"[*] Đang kiểm tra XXE trên: {target_url}\n")
    found_payloads = set()
    try:
        with open(XXE_PAYLOAD_FILE, "r", encoding="utf-8") as f:
            payloads = [line.strip().split('#')[0].strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception:
        output.write("[X] Không thể đọc file payloads/xxe.txt\n")
        return
    for payload in payloads:
        try:
            headers = {'Content-Type': 'application/xml'}
            res = requests.post(target_url, data=payload, headers=headers, timeout=7)
            text = res.text[:2000]
            for sign in XXE_SIGNS:
                if sign.lower() in text.lower():
                    found_payloads.add(payload)
                    break
            if res.status_code >= 500:
                found_payloads.add(payload)
        except Exception as e:
            output.write(f"[!] Lỗi khi gửi request: {e}\n")
    if found_payloads:
        output.write("[!] Có thể bị tấn công XXE với các payloads:\n")
        for payload in sorted(found_payloads):
            output.write(f"    - {payload}\n")
    else:
        output.write("[✓] Không phát hiện lỗ hổng XXE.\n")
    output.write("\n")
