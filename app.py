from flask import Flask, request, render_template, jsonify, redirect, url_for
from scanners.sqli import scan_sqli
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
    try:
        scan_sqli(url, output)
        full_result = output.getvalue()
        short = "Có thể bị SQLi!" if "payload" in full_result else "Không phát hiện SQLi."
        save_result(url, full_result)
        return jsonify(success=True, short=short, full=full_result)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route("/history")
def history():
    history_data = []
    if os.path.exists(HISTORY_DIR):
        for filename in os.listdir(HISTORY_DIR):
            if filename.endswith(".txt"):
                domain = filename.replace(".txt", "")
                filepath = os.path.join(HISTORY_DIR, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                mtime_raw = os.path.getmtime(filepath)
                mtime = datetime.fromtimestamp(mtime_raw)
                history_data.append({
                    "domain": domain,
                    "filename": filename,  # nếu cần
                    "time": mtime,
                    "content": content
                })

    # Sắp xếp theo thời gian mới nhất
    history_data.sort(key=lambda x: x["time"], reverse=True)

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

def save_result(url, result):
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)
    domain = urlparse(url).netloc
    time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{domain}__{time_str}.txt"
    filepath = os.path.join(HISTORY_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"[TIME] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n[URL] {url}\n{result}\n")

if __name__ == "__main__":
    app.run(debug=True)
