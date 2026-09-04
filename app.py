from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

import os
import inspect

from backend.scanner.iam_scanner import IAMScanner
from backend.scanner.ec2_scanner import EC2Scanner
from backend.scanner.s3_scanner import S3Scanner
from backend.scanner.security_group_scanner import SecurityGroupScanner
from backend.scanner.device_scanner import DeviceScanner

from backend.risk_engine import RiskEngine
from backend.system_info import get_system_info

from backend.history_manager import save_scan, get_history

from backend.advisor import SecurityAdvisor
from backend.compliance import ComplianceEngine
from backend.alert_engine import AlertEngine
from backend.report_generator import generate_pdf

from database import create_user_table, get_db_connection


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cyberguardx-development-secret-key"
)


# ============================================================
# SESSION CONFIGURATION
# ============================================================

app.config["SESSION_COOKIE_NAME"] = "cyberguardx_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("VERCEL"))
app.config["PERMANENT_SESSION_LIFETIME"] = 86400


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

try:
    create_user_table()
    print("CyberGuardX database initialized successfully.")
except Exception as e:
    print("DATABASE INITIALIZATION ERROR:", repr(e))


# ============================================================
# CLOUD SECURITY DATA
# ============================================================

security_score = 0
security_status = "Not Scanned"

system_info = {}

iam_result = []
ec2_result = []
s3_result = []
sg_result = []

risks = []
alerts = []
compliance_report = []
advisor_result = []

scan_history = []


# ============================================================
# DEVICE SECURITY DATA
# ============================================================

device_results = []

device_security_score = 0
device_security_status = "Not Scanned"

device_high_risks = 0
device_medium_risks = 0
device_low_risks = 0

device_recommendations = []


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_risk_level(item):

    if not isinstance(item, dict):
        return "Low"

    value = item.get(
        "level",
        item.get(
            "risk",
            item.get(
                "severity",
                "Low"
            )
        )
    )

    if not value:
        return "Low"

    return str(value).strip().title()


def count_risks(items):

    high = 0
    medium = 0
    low = 0

    for item in items or []:

        risk_level = get_risk_level(item)

        if risk_level == "High":
            high += 1

        elif risk_level == "Medium":
            medium += 1

        else:
            low += 1

    return high, medium, low


def security_status_from_score(score):

    if score >= 85:
        return "Excellent"

    if score >= 70:
        return "Good"

    if score >= 50:
        return "Needs Attention"

    return "Critical"


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if not session.get("logged_in"):
        return redirect("/register")

    return redirect("/dashboard")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            return render_template(
                "login.html",
                error="Please enter username and password."
            )

        connection = None

        try:

            connection = get_db_connection()

            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user is None:

                return render_template(
                    "login.html",
                    error="Username not found. Please register first."
                )

            if not check_password_hash(
                user["password"],
                password
            ):

                return render_template(
                    "login.html",
                    error="Wrong password."
                )

            session.clear()

            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            session.permanent = True

            print("LOGIN SUCCESS:", username)

            return redirect("/dashboard")

        except Exception as e:

            print(
                "LOGIN DATABASE ERROR:",
                repr(e)
            )

            return render_template(
                "login.html",
                error="Unable to login. Please try again."
            )

        finally:

            if connection:
                connection.close()

    return render_template(
        "login.html",
        error=None
    )


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not email or not password:

            return render_template(
                "register.html",
                error="Please fill in all fields."
            )

        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must contain at least 6 characters."
            )

        connection = None

        try:

            connection = get_db_connection()

            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
                """,
                (
                    username,
                    email
                )
            ).fetchone()

            if existing_user is not None:

                return render_template(
                    "register.html",
                    error="Username or email already exists. Please sign in."
                )

            hashed_password = generate_password_hash(
                password
            )

            connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    hashed_password
                )
            )

            connection.commit()

            print(
                "REGISTRATION SUCCESS:",
                username
            )

            flash(
                "Registration successful! Please sign in.",
                "success"
            )

            return redirect("/login")

        except Exception as e:

            print(
                "REGISTRATION DATABASE ERROR:",
                repr(e)
            )

            return render_template(
                "register.html",
                error="Unable to create account. Please try again."
            )

        finally:

            if connection:
                connection.close()

    return render_template(
        "register.html",
        error=None
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):
        return redirect("/login")

    dashboard_stats = {

        "iam_users": len(iam_result),

        "ec2_instances": len(ec2_result),

        "s3_buckets": len(s3_result),

        "security_groups": len(sg_result)

    }

    return render_template(

        "dashboard.html",

        score=security_score,

        status=security_status,

        dashboard_stats=dashboard_stats,

        device_security_score=device_security_score,

        device_security_status=device_security_status,

        scan_history=scan_history

    )


# ============================================================
# DASHBOARD SLASH
# ============================================================

@app.route("/dashboard/")
def dashboard_slash():

    return redirect("/dashboard")


# ============================================================
# CLOUD SECURITY SCAN
# ============================================================

@app.route("/scan")
def scan():

    if not session.get("logged_in"):
        return redirect("/login")

    global security_score
    global security_status
    global system_info

    global iam_result
    global ec2_result
    global s3_result
    global sg_result

    global risks
    global alerts
    global compliance_report
    global advisor_result

    global scan_history

    try:

        print("===================================")
        print("STARTING CLOUD SECURITY SCAN")
        print("===================================")

        # ----------------------------------------------------
        # SYSTEM INFORMATION
        # ----------------------------------------------------

        system_info = get_system_info()

        # ----------------------------------------------------
        # IAM
        # ----------------------------------------------------

        iam_result = IAMScanner().scan()

        # ----------------------------------------------------
        # EC2
        # ----------------------------------------------------

        ec2_result = EC2Scanner().scan()

        # ----------------------------------------------------
        # S3
        # ----------------------------------------------------

        s3_result = S3Scanner().scan()

        # ----------------------------------------------------
        # SECURITY GROUP
        # ----------------------------------------------------

        sg_result = SecurityGroupScanner().scan()

        # ----------------------------------------------------
        # RISK ENGINE
        # ----------------------------------------------------

        risk_result = RiskEngine().calculate_score(

            iam_result,
            ec2_result,
            s3_result,
            sg_result

        )

        security_score = int(
            risk_result.get(
                "score",
                0
            )
        )

        risks = risk_result.get(
            "risks",
            []
        )

        security_status = risk_result.get(
            "status",
            security_status_from_score(
                security_score
            )
        )

        # ----------------------------------------------------
        # COMPLIANCE
        # ----------------------------------------------------

        compliance_report = (
            ComplianceEngine()
            .generate_report(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )

        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        alerts = (
            AlertEngine()
            .generate_alerts(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )

        # ----------------------------------------------------
        # SECURITY ADVISOR
        # ----------------------------------------------------

        advisor_result = (
            SecurityAdvisor()
            .generate_advice(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )

        # ----------------------------------------------------
        # RISK COUNTS
        # ----------------------------------------------------

        high, medium, low = count_risks(
            risks
        )

        # ----------------------------------------------------
        # SAVE HISTORY
        # ----------------------------------------------------

        save_scan(

            security_score,

            security_status,

            high,

            medium,

            low

        )

        scan_history = get_history()

        # ----------------------------------------------------
        # CLOUD STATISTICS
        # ----------------------------------------------------

        dashboard_stats = {

            "iam_users": len(iam_result),

            "ec2_instances": len(ec2_result),

            "s3_buckets": len(s3_result),

            "security_groups": len(sg_result)

        }

        print("CLOUD SCAN COMPLETED")

        # ----------------------------------------------------
        # CLOUD REPORT
        # ----------------------------------------------------

        return render_template(

            "scan_results.html",

            scan_type="cloud",

            score=security_score,

            status=security_status,

            dashboard_stats=dashboard_stats,

            system_info=system_info,

            iam_result=iam_result,

            ec2_result=ec2_result,

            s3_result=s3_result,

            sg_result=sg_result,

            risks=risks,

            alerts=alerts,

            compliance_report=compliance_report,

            advisor_result=advisor_result,

            scan_history=scan_history

        )

    except Exception as e:

        print(
            "CLOUD SCAN ERROR:",
            repr(e)
        )

        return render_template(

            "dashboard.html",

            score=security_score,

            status=security_status,

            dashboard_stats={

                "iam_users": len(iam_result),

                "ec2_instances": len(ec2_result),

                "s3_buckets": len(s3_result),

                "security_groups": len(sg_result)

            },

            device_security_score=device_security_score,

            device_security_status=device_security_status,

            scan_history=scan_history

        )


# ============================================================
# DEVICE SECURITY SCAN
# ============================================================

@app.route("/device-scan")
def device_scan():

    if not session.get("logged_in"):
        return redirect("/login")

    global device_results

    global device_security_score
    global device_security_status

    global device_high_risks
    global device_medium_risks
    global device_low_risks

    global device_recommendations

    try:

        print("===================================")
        print("STARTING DEVICE SECURITY SCAN")
        print("===================================")

        # ----------------------------------------------------
        # RUN DEVICE SCANNER
        # ----------------------------------------------------

        device_results = DeviceScanner().scan()

        print("DEVICE RESULTS:")
        print(device_results)

        # ----------------------------------------------------
        # ENSURE LIST
        # ----------------------------------------------------

        if not isinstance(
            device_results,
            list
        ):

            device_results = []

        # ----------------------------------------------------
        # DEVICE RISK COUNTS
        # ----------------------------------------------------

        (
            device_high_risks,
            device_medium_risks,
            device_low_risks
        ) = count_risks(
            device_results
        )

        # ----------------------------------------------------
        # DEVICE SCORE
        # ----------------------------------------------------

        device_security_score = max(

            0,

            100

            - (
                device_high_risks * 15
            )

            - (
                device_medium_risks * 7
            )

            - device_low_risks

        )

        # ----------------------------------------------------
        # DEVICE STATUS
        # ----------------------------------------------------

        device_security_status = (
            security_status_from_score(
                device_security_score
            )
        )

        # ----------------------------------------------------
        # DEVICE RECOMMENDATIONS
        # ----------------------------------------------------

        device_recommendations = []

        if device_high_risks > 0:

            device_recommendations.append(
                "Review all high-risk device findings immediately."
            )

        if device_medium_risks > 0:

            device_recommendations.append(
                "Investigate medium-risk findings and reduce unnecessary exposure."
            )

        if device_low_risks > 0:

            device_recommendations.append(
                "Review low-risk findings during routine maintenance."
            )

        device_recommendations.extend([

            "Keep the operating system and security software updated.",

            "Disable unnecessary services and listening ports.",

            "Use a firewall and avoid exposing unnecessary network services."

        ])

        # ----------------------------------------------------
        # DEVICE SYSTEM INFORMATION
        # ----------------------------------------------------

        current_system_info = get_system_info()

        print(
            "DEVICE SCORE:",
            device_security_score
        )

        print(
            "DEVICE STATUS:",
            device_security_status
        )

        print(
            "DEVICE SCAN COMPLETED"
        )

        # ----------------------------------------------------
        # DEVICE REPORT
        #
        # THIS IS THE IMPORTANT FIX.
        #
        # Device scan uses:
        #
        # device_results.html
        #
        # NOT:
        #
        # scan_results.html
        # ----------------------------------------------------

        return render_template(

            "device_results.html",

            device_score=device_security_score,

            security_status=device_security_status,

            high_risks=device_high_risks,

            medium_risks=device_medium_risks,

            low_risks=device_low_risks,

            device_results=device_results,

            recommendations=device_recommendations,

            system_info=current_system_info

        )

    except Exception as e:

        print("===================================")
        print("DEVICE SCAN ERROR:")
        print(repr(e))
        print("===================================")

        return render_template(

            "dashboard.html",

            score=security_score,

            status=security_status,

            dashboard_stats={

                "iam_users": len(iam_result),

                "ec2_instances": len(ec2_result),

                "s3_buckets": len(s3_result),

                "security_groups": len(sg_result)

            },

            device_security_score=device_security_score,

            device_security_status=device_security_status,

            scan_history=scan_history

        )


# ============================================================
# DOWNLOAD SECURITY REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    if not session.get("logged_in"):
        return redirect("/login")

    try:

        signature = inspect.signature(
            generate_pdf
        )

        parameter_count = len(
            signature.parameters
        )

        # ----------------------------------------------------
        # NEW REPORT GENERATOR
        # ----------------------------------------------------

        if parameter_count == 1:

            report_data = {

                "security_score": security_score,

                "security_status": security_status,

                "system_info": system_info,

                "iam_result": iam_result,

                "ec2_result": ec2_result,

                "s3_result": s3_result,

                "sg_result": sg_result,

                "advisor_result": advisor_result,

                "scan_history": scan_history

            }

            return generate_pdf(
                report_data
            )

        # ----------------------------------------------------
        # OLD REPORT GENERATOR
        # ----------------------------------------------------

        return generate_pdf(

            security_score,

            system_info,

            iam_result,

            ec2_result,

            s3_result,

            sg_result,

            advisor_result,

            scan_history

        )

    except Exception as e:

        print(
            "REPORT GENERATION ERROR:",
            repr(e)
        )

        return redirect("/dashboard")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect("/login")


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        repr(error)
    )

    return """
    <html>
    <head>

        <title>CyberGuardX - Server Error</title>

        <style>

            body {
                background: #020617;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                text-align: center;
            }

            .box {
                max-width: 600px;
                padding: 40px;
                border: 1px solid #334155;
                border-radius: 20px;
                background: #0f172a;
            }

            h1 {
                color: #60a5fa;
            }

            a {
                color: #60a5fa;
            }

        </style>

    </head>

    <body>

        <div class="box">

            <h1>CyberGuardX</h1>

            <h2>Something went wrong.</h2>

            <p>
                The server encountered an unexpected error.
            </p>

            <a href="/dashboard">
                Return to Dashboard
            </a>

        </div>

    </body>
    </html>
    """, 500


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    print("""
===================================
CyberGuardX is starting...
Open: http://127.0.0.1:5000
===================================
""")

    app.run(

        host="0.0.0.0",

        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),

        debug=True

    )