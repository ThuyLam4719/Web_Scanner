import requests
import json
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# --- Hàm chèn payload vào tham số URL ---
def chen_payload_vao_url(url, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query, keep_blank_values=True)

    if not query:
        return None

    new_query = {}
    for key in query:
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

# --- Hàm lấy tất cả form từ trang ---
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
                inputs[name] = 'test'  # Giá trị mặc định sẽ được ghi đè bởi payload

            danh_sach_forms.append({
                "url": form_url,
                "method": method,
                "data": inputs
            })

        return danh_sach_forms

    except Exception:
        return []

# --- Hàm quét SQLi (GET hoặc POST hoặc FORM) ---
def scan_sqli(target_url, output):
    output.write("======= SQLi =======\n")
    output.write("\n")
    output.write("[*] Đang kiểm tra SQL Injection trên: {}\n".format(target_url))

    parsed = urlparse(target_url)
    has_params = bool(parse_qs(parsed.query, keep_blank_values=True))

    payload_nguy_hiem = []
    danh_sach_file = [
        "payloads/error_based.txt",
        "payloads/boolean_based.txt",
        "payloads/time_based.txt"
    ]

    # Trường hợp URL có tham số: test trực tiếp trên URL
    if has_params:
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
                    continue

                try:
                    res = requests.get(url_kiem_tra, timeout=5)
                    tu_khoa = ["mysql", "sql syntax", "warning", "ORA-", "syntax error", "unterminated"]
                    for tu in tu_khoa:
                        if tu.lower() in res.text.lower():
                            payload_nguy_hiem.append(payload)
                            break
                except Exception as loi:
                    output.write("[!] Lỗi khi gửi request: {}\n".format(loi))

    # Nếu không có tham số thì thử lấy FORM
    else:
        output.write("[!] URL không chứa tham số. Đang thử tìm form để kiểm tra...\n")
        forms = trich_form(target_url)

        if not forms:
            output.write("[X] Không tìm thấy form để kiểm tra.\n")
            output.write("[✓] Không thể thực hiện kiểm tra SQLi.\n\n")
            return

        for form in forms:
            input_names = list(form['data'].keys())
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
                    # Thử từng input một với payload, các input còn lại giữ giá trị mặc định
                    for input_name in input_names:
                        data_gui = {}
                        for k in input_names:
                            if k == input_name:
                                data_gui[k] = form['data'][k] + payload
                            else:
                                data_gui[k] = form['data'][k]
                        try:
                            if form['method'] == 'post':
                                res = requests.post(form['url'], data=data_gui, timeout=5)
                            else:
                                res = requests.get(form['url'], params=data_gui, timeout=5)

                            tu_khoa = ["mysql", "sql syntax", "warning", "ORA-", "syntax error", "unterminated"]
                            for tu in tu_khoa:
                                if tu.lower() in res.text.lower():
                                    payload_nguy_hiem.append(f"{input_name}={payload}")
                                    break
                        except Exception as loi:
                            output.write("[!] Lỗi khi gửi request đến form: {}\n".format(loi))

    # Ghi kết quả ra output
    if payload_nguy_hiem:
        output.write("[!] Có thể bị tấn công SQLi với các payloads:\n")
        for p in payload_nguy_hiem:
            output.write("    - {}\n".format(p))
    else:
        output.write("[✓] Không phát hiện lỗ hổng SQLi.\n")
    output.write("\n")

    # --- Ghi vào lịch sử ---
    scan_result = output.getvalue()
    entry = {
        "domain": target_url,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "result": scan_result
    }

    try:
        with open("history.json", "r") as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        history = []

    history.append(entry)

    with open("history.json", "w") as f:
        json.dump(history, f, indent=2)
