from flask import Flask, request, render_template, jsonify, redirect, url_for
from scanners.sqli import scan_sqli
from scanners.xss import scan_xss
from io import StringIO
import os
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
HISTORY_DIR = "history"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")
    output = StringIO()
    # Quét SQLi
    try:
        scan_sqli(url, output)
        sqli_result = output.getvalue()
    except Exception as e:
        sqli_result = f"[Lỗi SQLi] {e}\n"
    # Quét XSS
    output2 = StringIO()
    try:
        scan_xss(url, output2)
        xss_result = output2.getvalue()
    except Exception as e:
        xss_result = f"[Lỗi XSS] {e}\n"
    # Tổng hợp kết quả
    all_result = sqli_result + "\n" + xss_result
    vulns = []
    if ("Có thể bị tấn công SQLi" in sqli_result) or ("payload" in sqli_result and "Không phát hiện lỗ hổng SQLi" not in sqli_result):
        vulns.append("SQLi")
    if ("Có thể bị tấn công XSS" in xss_result) or ("Phát hiện XSS" in xss_result):
        vulns.append("XSS")
    short = ", ".join(vulns) if vulns else "AN TOÀN"
    save_result(url, all_result, vuln_type=short)
    return jsonify(success=True, short=short, full=all_result)

@app.route("/history")
def history():
    history_data = []
    if os.path.exists(HISTORY_DIR):
        for filename in os.listdir(HISTORY_DIR):
            if filename.endswith(".txt"):
                domain = filename.split("__")[0]
                filepath = os.path.join(HISTORY_DIR, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                mtime_raw = os.path.getmtime(filepath)
                mtime = datetime.fromtimestamp(mtime_raw)
                # Luôn phân tích nội dung để lấy danh sách lỗ hổng
                vuln_name = []
                if "payload" in content or "SQLi" in content or "sqli" in content:
                    vuln_name.append("SQLi")
                if "Có thể bị tấn công XSS" in content or "Phát hiện XSS" in content:
                    vuln_name.append("XSS")
                vuln_name = ", ".join(vuln_name) if vuln_name else "AN TOÀN"
                history_data.append({
                    "domain": domain,
                    "filename": filename,
                    "time": mtime,
                    "content": content,
                    "vuln_name": vuln_name
                })
    # Sắp xếp theo thời gian mới nhất
    history_data.sort(key=lambda x: x["time"], reverse=False)
    # Gán STT và định dạng thời gian
    for idx, entry in enumerate(history_data):
        entry["stt"] = idx + 1
        entry["time"] = entry["time"].strftime("%Y-%m-%d %H:%M:%S")
    return render_template("history.html", history=history_data)

@app.route("/history/<filename>")
def view_result(filename):
    filepath = os.path.join(HISTORY_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        domain, timestamp_str = filename.replace(".txt", "").split("__")
        return render_template("result.html", domain=domain, content=content)
    return "Không tìm thấy kết quả", 404

@app.route("/delete/<filename>", methods=["POST"])
def delete_result(filename):
    filepath = os.path.join(HISTORY_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    return redirect(url_for("history"))

def save_result(url, result, vuln_type=None):
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)
    domain = urlparse(url).netloc
    time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    if vuln_type and vuln_type != "AN TOÀN":
        filename = f"{domain}__{time_str}__{vuln_type}.txt"
    else:
        filename = f"{domain}__{time_str}.txt"
    filepath = os.path.join(HISTORY_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"[TIME] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n[URL] {url}\n{result}\n")

if __name__ == "__main__":
    app.run(debug=True)
