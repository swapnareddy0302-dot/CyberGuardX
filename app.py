from flask import Flask, render_template, request
from backend.scanner.iam_scanner import IAMScanner
from backend.system_info import get_system_info   # <-- Add this line

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    scanner = IAMScanner()

    # Get system information
    system_info = get_system_info()

    results = {
        "Total Users": "-",
        "MFA Enabled": "-",
        "Admin Users": "-",
        "Inactive Users": "-",
        "Security Score": "-"
    }

    score_color = "green"

    if request.method == "POST":

        results = scanner.scan()

        score = results["Security Score"]

        if score >= 80:
            score_color = "green"
        elif score >= 50:
            score_color = "orange"
        else:
            score_color = "red"

    return render_template(
        "index.html",
        results=results,
        score_color=score_color,
        system_info=system_info
    )


if __name__ == "__main__":
    app.run(debug=True)