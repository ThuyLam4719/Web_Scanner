from flask import Flask, request, render_template, jsonify
from scanners.sqli import scan_sqli
from io import StringIO
import os

app = Flask(__name__)
HISTORY_FILE = "scan_history.txt"

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
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = f.read().split("====")
            history = {}
            for block in lines:
                if block.strip():
                    parts = block.strip().split("\n", 1)
                    history[parts[0]] = parts[1] if len(parts) > 1 else ""
            return render_template("history.html", history=history)
    return render_template("history.html", history={})

def save_result(url, result):
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(f"{url}\n{result}\n====\n")

if __name__ == "__main__":
    app.run(debug=True)
