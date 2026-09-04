from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

import os
import inspect


# ============================================================
# CYBERGUARDX BACKEND IMPORTS
# ============================================================

from backend.scanner.iam_scanner import IAMScanner
from backend.scanner.ec2_scanner import EC2Scanner
from backend.scanner.s3_scanner import S3Scanner
from backend.scanner.security_group_scanner import SecurityGroupScanner
from backend.scanner.device_scanner import DeviceScanner

from backend.risk_engine import RiskEngine
from backend.system_info import get_system_info

from backend.history_manager import (
    save_scan,
    get_history
)

from backend.advisor import SecurityAdvisor
from backend.compliance import ComplianceEngine
from backend.alert_engine import AlertEngine
from backend.report_generator import generate_pdf

from database import (
    create_user_table,
    get_db_connection
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# SECRET KEY
# ============================================================

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

# HTTPS is used on Vercel
app.config["SESSION_COOKIE_SECURE"] = bool(
    os.environ.get("VERCEL")
)

app.config["PERMANENT_SESSION_LIFETIME"] = 86400


# ============================================================
# CREATE DATABASE TABLE
# ============================================================

try:
    create_user_table()
    print("CyberGuardX database initialized successfully.")

except Exception as e:
    print("DATABASE INITIALIZATION ERROR:", e)


# ============================================================
# GLOBAL SECURITY DATA
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
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    # First-time visitor
    # goes to registration page

    if not session.get("logged_in"):
        return redirect("/register")

    return redirect("/dashboard")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        print("========== LOGIN DEBUG ==========")
        print("Username received:", repr(username))
        print("Password received:", "YES" if password else "NO")

        if not username or not password:
            print("LOGIN FAILED: EMPTY INPUT")

            return render_template(
                "login.html",
                error="DEBUG: Username or password was empty."
            )

        connection = None

        try:

            print("Connecting to database...")

            connection = get_db_connection()

            print("Database connection successful.")

            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            print("User lookup result:", user)

            if user is None:

                print("LOGIN FAILED: USER NOT FOUND")

                return render_template(
                    "login.html",
                    error="DEBUG: Username not found in database."
                )

            print("User found.")

            password_matches = check_password_hash(
                user["password"],
                password
            )

            print("Password matches:", password_matches)

            if not password_matches:

                print("LOGIN FAILED: WRONG PASSWORD")

                return render_template(
                    "login.html",
                    error="DEBUG: Password verification failed."
                )

            print("LOGIN SUCCESS!")

            session.clear()

            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True

            print("Session created.")
            print("Redirecting to dashboard...")

            return redirect("/dashboard")

        except Exception as e:

            print("========== LOGIN EXCEPTION ==========")
            print(repr(e))

            return render_template(
                "login.html",
                error=f"DEBUG DATABASE ERROR: {str(e)}"
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


        # --------------------------------------------
        # Validate fields
        # --------------------------------------------

        if not username or not email or not password:

            return render_template(
                "register.html",
                error="Please fill in all fields."
            )


        # --------------------------------------------
        # Password validation
        # --------------------------------------------

        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must contain at least 6 characters."
            )


        connection = None

        try:

            # ----------------------------------------
            # Database connection
            # ----------------------------------------

            connection = get_db_connection()


            # ----------------------------------------
            # Check existing username/email
            # ----------------------------------------

            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
                """,
                (username, email)
            ).fetchone()


            if existing_user is not None:

                return render_template(
                    "register.html",
                    error="Username or email already exists. Please sign in."
                )


            # ----------------------------------------
            # Hash password
            # ----------------------------------------

            hashed_password = generate_password_hash(
                password
            )


            # ----------------------------------------
            # Insert user
            # ----------------------------------------

            connection.execute(
                """
                INSERT INTO users
                (username, email, password)
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
                e
            )

            return render_template(
                "register.html",
                error="Unable to create account. Please try again."
            )


        finally:

            if connection:

                connection.close()


    # GET request

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


    stats = {

        "iam_users": len(iam_result),

        "ec2_instances": len(ec2_result),

        "s3_buckets": len(s3_result),

        "security_groups": len(sg_result)

    }


    return render_template(

        "dashboard.html",

        score=security_score,

        status=security_status,

        dashboard_stats=stats,

        device_security_score=device_security_score,

        device_security_status=device_security_status,

        scan_history=scan_history

    )


# ============================================================
# ROOT DASHBOARD COMPATIBILITY ROUTE
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

        # --------------------------------------------
        # System information
        # --------------------------------------------

        system_info = get_system_info()


        # --------------------------------------------
        # IAM
        # --------------------------------------------

        iam_result = IAMScanner().scan()


        # --------------------------------------------
        # EC2
        # --------------------------------------------

        ec2_result = EC2Scanner().scan()


        # --------------------------------------------
        # S3
        # --------------------------------------------

        s3_result = S3Scanner().scan()


        # --------------------------------------------
        # Security Groups
        # --------------------------------------------

        sg_result = SecurityGroupScanner().scan()


        # --------------------------------------------
        # Risk Engine
        # --------------------------------------------

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


        # --------------------------------------------
        # Compliance
        # --------------------------------------------

        compliance_report = (
            ComplianceEngine()
            .generate_report(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )


        # --------------------------------------------
        # Alerts
        # --------------------------------------------

        alerts = (
            AlertEngine()
            .generate_alerts(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )


        # --------------------------------------------
        # Security Advisor
        # --------------------------------------------

        advisor_result = (
            SecurityAdvisor()
            .generate_advice(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )
        )


        # --------------------------------------------
        # Risk counts
        # --------------------------------------------

        high, medium, low = count_risks(
            risks
        )


        # --------------------------------------------
        # Save scan history
        # --------------------------------------------

        save_scan(

            security_score,

            security_status,

            high,

            medium,

            low

        )


        scan_history = get_history()


        # --------------------------------------------
        # Dashboard statistics
        # --------------------------------------------

        dashboard_stats = {

            "iam_users": len(iam_result),

            "ec2_instances": len(ec2_result),

            "s3_buckets": len(s3_result),

            "security_groups": len(sg_result)

        }


        # --------------------------------------------
        # Cloud report
        # --------------------------------------------

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

            scan_history=scan_history,

            device_results=device_results,

            device_security_score=device_security_score,

            device_security_status=device_security_status,

            device_high_risks=device_high_risks,

            device_medium_risks=device_medium_risks,

            device_low_risks=device_low_risks,

            device_recommendations=device_recommendations

        )


    except Exception as e:

        print(
            "CLOUD SCAN ERROR:",
            e
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

        # --------------------------------------------
        # Device scanner
        # --------------------------------------------

        device_results = (
            DeviceScanner()
            .scan()
        )


        # --------------------------------------------
        # Risk counts
        # --------------------------------------------

        (
            device_high_risks,
            device_medium_risks,
            device_low_risks
        ) = count_risks(
            device_results
        )


        # --------------------------------------------
        # Device security score
        # --------------------------------------------

        device_security_score = max(

            0,

            100

            - device_high_risks * 15

            - device_medium_risks * 7

            - device_low_risks

        )


        # --------------------------------------------
        # Device security status
        # --------------------------------------------

        device_security_status = (
            security_status_from_score(
                device_security_score
            )
        )


        # --------------------------------------------
        # Recommendations
        # --------------------------------------------

        device_recommendations = []


        if device_high_risks:

            device_recommendations.append(
                "Review all high-risk device findings immediately."
            )


        if device_medium_risks:

            device_recommendations.append(
                "Investigate medium-risk findings and reduce unnecessary exposure."
            )


        if device_low_risks:

            device_recommendations.append(
                "Review low-risk findings during routine maintenance."
            )


        device_recommendations += [

            "Keep the operating system and security software updated.",

            "Disable unnecessary services and listening ports.",

            "Use a firewall and avoid exposing unnecessary network services."

        ]


        # --------------------------------------------
        # Report
        # --------------------------------------------

        return render_template(

            "scan_results.html",

            scan_type="device",

            score=device_security_score,

            status=device_security_status,

            dashboard_stats={

                "iam_users": len(iam_result),

                "ec2_instances": len(ec2_result),

                "s3_buckets": len(s3_result),

                "security_groups": len(sg_result)

            },

            system_info=get_system_info(),

            iam_result=iam_result,

            ec2_result=ec2_result,

            s3_result=s3_result,

            sg_result=sg_result,

            risks=risks,

            alerts=alerts,

            compliance_report=compliance_report,

            advisor_result=advisor_result,

            scan_history=scan_history,

            device_results=device_results,

            device_security_score=device_security_score,

            device_security_status=device_security_status,

            device_high_risks=device_high_risks,

            device_medium_risks=device_medium_risks,

            device_low_risks=device_low_risks,

            device_recommendations=device_recommendations

        )


    except Exception as e:

        print(
            "DEVICE SCAN ERROR:",
            e
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
# DOWNLOAD SECURITY REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    if not session.get("logged_in"):

        return redirect("/login")


    try:

        # --------------------------------------------
        # Support both report generator versions
        # --------------------------------------------

        signature = inspect.signature(
            generate_pdf
        )


        parameter_count = len(
            signature.parameters
        )


        # New version
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


        # Old version
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
            e
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
        error
    )

    return """

    <html>

    <head>

        <title>CyberGuardX - Server Error</title>

        <style>

            body {
                background:#020617;
                color:white;
                font-family:Arial;
                display:flex;
                align-items:center;
                justify-content:center;
                min-height:100vh;
                text-align:center;
            }

            .box {
                max-width:600px;
                padding:40px;
                border:1px solid #334155;
                border-radius:20px;
                background:#0f172a;
            }

            h1 {
                color:#60a5fa;
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

            <a
                href="/dashboard"
                style="color:#60a5fa;"
            >
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

    print(
        """
===================================
CyberGuardX is starting...
Open: http://127.0.0.1:5000
===================================
"""
    )

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