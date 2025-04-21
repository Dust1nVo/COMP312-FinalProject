from flask import Flask, render_template, jsonify
import os

app = Flask(__name__)

LOG_PATH = "logs/alerts.log"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logs")
def get_logs():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            logs = f.readlines()[-50:]  # Only last 50 lines
    else:
        logs = ["No alerts yet."]
    return jsonify(logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
