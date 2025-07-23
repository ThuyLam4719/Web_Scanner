import requests
import os
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def chen_payload_vao_url(url, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query, keep_blank_values=True)

    if not query:
        return None  # Không có tham số nào để chèn payload

    new_query = {}
    for key in query:
        # Nếu giá trị rỗng thì thêm chuỗi rỗng trước payload
        original_value = query[key][0] if query[key] else ''
        new_query[key] = [original_value + payload]

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


def scan_sqli(target_url, output):
    output.write("[+] Đang kiểm tra SQL Injection trên: {}\n".format(target_url))
    payload_nguy_hiem = []

    danh_sach_file = [
        "payloads/error_based.txt",
        "payloads/boolean_based.txt",
        "payloads/time_based.txt"
    ]

    for ten_file in danh_sach_file:
        try:
            with open(ten_file, "r", encoding="utf-8") as f:
                danh_sach_payload = f.readlines()
        except:
            output.write("[X] Không thể đọc file: {}\n".format(ten_file))
            continue

        for dong in danh_sach_payload:
            payload = dong.strip()
            if not payload:
                continue

            url_kiem_tra = chen_payload_vao_url(target_url, payload)
            if not url_kiem_tra:
                output.write("[!] URL không chứa tham số để kiểm tra payload.\n")
                break

            try:
                res = requests.get(url_kiem_tra, timeout=5)
                tu_khoa = ["mysql", "sql syntax", "warning", "ORA-", "syntax error", "unterminated"]

                for tu in tu_khoa:
                    if tu.lower() in res.text.lower():
                        payload_nguy_hiem.append(payload)
                        break

            except Exception as loi:
                output.write("[!] Lỗi khi gửi request: {}\n".format(loi))

    if payload_nguy_hiem:
        output.write("[!] Có thể bị tấn công SQLi với các payloads:\n")
        for p in payload_nguy_hiem:
            output.write("    - {}\n".format(p))
    else:
        output.write("[✓] Không phát hiện lỗ hổng SQLi.\n")

    output.write("\n")
