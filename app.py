from flask import Flask, render_template, redirect, url_for
from scanner import scan_wifi
from db import init_db, save_scan, load_scans
from analyzer import analyze

app = Flask(__name__)

init_db()


@app.route("/")
def home():
    scans = load_scans()

    return render_template(
        "index.html",
        networks=scans.tail(30).to_dict("records")
    )


@app.route("/scan")
def scan():
    df = scan_wifi(mock=False)

    if not df.empty:
        save_scan(df)

    return redirect(url_for("home"))


@app.route("/demo-scan")
def demo_scan():
    df = scan_wifi(mock=True)

    if not df.empty:
        save_scan(df)

    return redirect(url_for("home"))


@app.route("/report")
def report():
    result = analyze()

    return render_template(
        "report.html",
        summary=result["summary"],
        networks=result["df"].to_dict("records"),
        weak=result["weak"].to_dict("records"),
        channels=result["channel_counts"].to_dict("records")
    )


if __name__ == "__main__":
    app.run(debug=True)