# ============================================================
# CyberGuardX
# Cloud & Device Security Intelligence Platform
# ============================================================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import generate_password_hash, check_password_hash

import os


# ============================================================
# DATABASE
# ============================================================

from database import (
    create_user_table,
    get_db_connection
)


# ============================================================
# CLOUD SECURITY SCANNERS
# ============================================================

from backend.scanner.iam_scanner import IAMScanner
from backend.scanner.ec2_scanner import EC2Scanner
from backend.scanner.s3_scanner import S3Scanner
from backend.scanner.security_group_scanner import SecurityGroupScanner


# ============================================================
# DEVICE SECURITY
# ============================================================

from backend.scanner.device_scanner import DeviceScanner


# ============================================================
# SECURITY ENGINES
# ============================================================

from backend.risk_engine import RiskEngine
from backend.advisor import SecurityAdvisor
from backend.compliance import ComplianceEngine
from backend.alert_engine import AlertEngine


# ============================================================
# HISTORY / SYSTEM INFORMATION / PDF
# ============================================================

from backend.history_manager import save_scan
from backend.system_info import get_system_info
from backend.report_generator import generate_pdf


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "CYBERGUARDX_SECRET_KEY",
    "cyberguardx_secret_key"
)


# ============================================================
# CREATE DATABASE TABLE
# ============================================================

create_user_table()


# ============================================================
# GLOBAL CLOUD SCAN DATA
# ============================================================

security_score = 0

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
# GLOBAL DEVICE SCAN DATA
# ============================================================

device_results = []

device_security_score = 0

device_high_risks = 0
device_medium_risks = 0
device_low_risks = 0

device_security_status = "Not Scanned"

device_recommendations = []


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_risk_level(item):
    """
    Extract risk level from different scanner/risk-engine
    dictionary formats.
    """

    if not isinstance(item, dict):
        return "Low"

    level = item.get(
        "level",
        item.get(
            "risk",
            item.get(
                "severity",
                "Low"
            )
        )
    )

    return str(level).strip().lower()


# ============================================================

def count_risks(items):
    """
    Count High / Medium / Low risks.
    """

    high = 0
    medium = 0
    low = 0

    if not isinstance(items, list):
        return high, medium, low

    for item in items:

        level = get_risk_level(item)

        if level == "high":
            high += 1

        elif level == "medium":
            medium += 1

        else:
            low += 1

    return high, medium, low


# ============================================================

def get_security_status(score):
    """
    Convert security score into a readable status.
    """

    try:
        score = int(score)
    except Exception:
        score = 0

    if score < 30:
        return "Critical"

    elif score < 50:
        return "High Risk"

    elif score < 70:
        return "Warning"

    elif score < 85:
        return "Good"

    else:
        return "Excellent"


# ============================================================

def calculate_device_score(
    high_risks,
    medium_risks,
    low_risks
):
    """
    Calculate device security score.

    High   = -15
    Medium = -7
    Low    = -1
    """

    score = 100

    score -= high_risks * 15
    score -= medium_risks * 7
    score -= low_risks * 1

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    return score


# ============================================================

def get_device_status(score):
    """
    Device security status.
    """

    try:
        score = int(score)
    except Exception:
        score = 0

    if score < 30:
        return "Critical"

    elif score < 50:
        return "High Risk"

    elif score < 70:
        return "Warning"

    elif score < 85:
        return "Good"

    else:
        return "Excellent"


# ============================================================

def generate_device_recommendations(
    high_risks,
    medium_risks,
    low_risks
):
    """
    Generate simple recommendations based on
    local device findings.
    """

    recommendations = []

    if high_risks > 0:

        recommendations.append(
            "Immediately investigate all high-risk device findings."
        )

    if medium_risks > 0:

        recommendations.append(
            "Review medium-risk findings and apply appropriate security controls."
        )

    if low_risks > 0:

        recommendations.append(
            "Continue monitoring low-risk system conditions."
        )

    if high_risks == 0 and medium_risks == 0:

        recommendations.append(
            "No high or medium risk conditions were detected during the device scan."
        )

    recommendations.append(
        "Keep the operating system, applications and security software updated."
    )

    recommendations.append(
        "Use strong authentication and avoid unnecessary administrative privileges."
    )

    return recommendations


# ============================================================
# LOGIN REQUIRED DECORATOR-LIKE CHECK
# ============================================================

def is_logged_in():
    return session.get("logged_in", False)


# ============================================================
# HOME / DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    if not is_logged_in():

        return redirect(
            url_for("register")
        )

    return render_template(
        "dashboard.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ----------------------------------------------------
        # Empty fields
        # ----------------------------------------------------

        if not username or not email or not password:

            flash(
                "Please fill in all required fields.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        # ----------------------------------------------------
        # Password length
        # ----------------------------------------------------

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        # ----------------------------------------------------
        # Password confirmation
        # ----------------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        # ----------------------------------------------------
        # Check existing account
        # ----------------------------------------------------

        connection = get_db_connection()

        existing_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?
            """,
            (
                username,
                email
            )
        ).fetchone()


        if existing_user:

            connection.close()

            flash(
                "An account with this username or email already exists. Please sign in.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        # ----------------------------------------------------
        # Hash password
        # ----------------------------------------------------

        hashed_password = generate_password_hash(
            password
        )


        # ----------------------------------------------------
        # Insert user
        # ----------------------------------------------------

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
        connection.close()


        # ----------------------------------------------------
        # Success
        # ----------------------------------------------------

        flash(
            "Account created successfully. Please sign in.",
            "success"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
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


        # ----------------------------------------------------
        # Empty fields
        # ----------------------------------------------------

        if not username or not password:

            flash(
                "Please enter username and password.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        # ----------------------------------------------------
        # Find user
        # ----------------------------------------------------

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()


        # ----------------------------------------------------
        # Validate credentials
        # ----------------------------------------------------

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]


            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )


        # ----------------------------------------------------
        # Invalid credentials
        # ----------------------------------------------------

        flash(
            "Invalid username or password.",
            "error"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "login.html"
    )


# ============================================================
# CLOUD SECURITY SCAN
# ============================================================

@app.route("/scan")
def scan():

    global security_score
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


    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    try:

        print()
        print("========================================")
        print("CyberGuardX Cloud Security Scan")
        print("========================================")


        # ====================================================
        # 1. SYSTEM INFORMATION
        # ====================================================

        try:

            system_info = get_system_info()

            if system_info is None:
                system_info = {}

            print(
                "✓ System information collected"
            )

        except Exception as e:

            print(
                "System information error:",
                e
            )

            system_info = {
                "status": "Unavailable",
                "error": str(e)
            }


        # ====================================================
        # 2. IAM SCAN
        # ====================================================

        try:

            iam_result = IAMScanner().scan()

            if iam_result is None:
                iam_result = []

            print(
                f"✓ IAM scan completed: {len(iam_result)} results"
            )

        except Exception as e:

            print(
                "IAM Scanner Error:",
                e
            )

            iam_result = [{
                "status": "Scanner Error",
                "details": str(e),
                "risk": "Medium"
            }]


        # ====================================================
        # 3. EC2 SCAN
        # ====================================================

        try:

            ec2_result = EC2Scanner().scan()

            if ec2_result is None:
                ec2_result = []

            print(
                f"✓ EC2 scan completed: {len(ec2_result)} results"
            )

        except Exception as e:

            print(
                "EC2 Scanner Error:",
                e
            )

            ec2_result = [{
                "status": "Scanner Error",
                "details": str(e),
                "risk": "Medium"
            }]


        # ====================================================
        # 4. S3 SCAN
        # ====================================================

        try:

            s3_result = S3Scanner().scan()

            if s3_result is None:
                s3_result = []

            print(
                f"✓ S3 scan completed: {len(s3_result)} results"
            )

        except Exception as e:

            print(
                "S3 Scanner Error:",
                e
            )

            s3_result = [{
                "status": "Scanner Error",
                "details": str(e),
                "risk": "Medium"
            }]


        # ====================================================
        # 5. SECURITY GROUP SCAN
        # ====================================================

        try:

            sg_result = SecurityGroupScanner().scan()

            if sg_result is None:
                sg_result = []

            print(
                f"✓ Security Group scan completed: {len(sg_result)} results"
            )

        except Exception as e:

            print(
                "Security Group Scanner Error:",
                e
            )

            sg_result = [{
                "status": "Scanner Error",
                "details": str(e),
                "risk": "Medium"
            }]


        # ====================================================
        # 6. RISK ENGINE
        # ====================================================

        try:

            risk_result = RiskEngine().calculate_score(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )


            if isinstance(
                risk_result,
                dict
            ):

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

                if risks is None:
                    risks = []

            else:

                security_score = 0
                risks = []


            print(
                f"✓ Risk engine completed: {security_score}/100"
            )


        except Exception as e:

            print(
                "Risk Engine Error:",
                e
            )

            security_score = 0

            risks = [{
                "level": "High",
                "title": "Risk Engine Error",
                "description": str(e)
            }]


        # ====================================================
        # 7. SECURITY STATUS
        # ====================================================

        security_status = get_security_status(
            security_score
        )


        # ====================================================
        # 8. COMPLIANCE ENGINE
        # ====================================================

        try:

            compliance_report = ComplianceEngine().generate_report(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )

            if compliance_report is None:
                compliance_report = []

            print(
                "✓ Compliance analysis completed"
            )

        except Exception as e:

            print(
                "Compliance Engine Error:",
                e
            )

            compliance_report = [{
                "control": "Compliance Engine",
                "status": str(e)
            }]


        # ====================================================
        # 9. ALERT ENGINE
        # ====================================================

        try:

            alerts = AlertEngine().generate_alerts(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )

            if alerts is None:
                alerts = []

            print(
                f"✓ Alert analysis completed: {len(alerts)} alerts"
            )

        except Exception as e:

            print(
                "Alert Engine Error:",
                e
            )

            alerts = [{
                "title": "Alert Engine Error",
                "message": str(e),
                "level": "Medium"
            }]


        # ====================================================
        # 10. SECURITY ADVISOR
        # ====================================================

        try:

            advisor_result = SecurityAdvisor().generate_advice(
                iam_result,
                ec2_result,
                s3_result,
                sg_result
            )

            if advisor_result is None:
                advisor_result = []

            print(
                "✓ Security Advisor completed"
            )

        except Exception as e:

            print(
                "Security Advisor Error:",
                e
            )

            advisor_result = [{
                "recommendation":
                    f"Security Advisor error: {e}"
            }]


        # ====================================================
        # 11. DASHBOARD STATISTICS
        # ====================================================

        dashboard_stats = {

            "iam_users":
                len(iam_result)
                if isinstance(
                    iam_result,
                    list
                )
                else 0,

            "ec2_instances":
                len(ec2_result)
                if isinstance(
                    ec2_result,
                    list
                )
                else 0,

            "s3_buckets":
                len(s3_result)
                if isinstance(
                    s3_result,
                    list
                )
                else 0,

            "security_groups":
                len(sg_result)
                if isinstance(
                    sg_result,
                    list
                )
                else 0
        }


        # ====================================================
        # 12. RISK COUNTS
        # ====================================================

        high_risks, medium_risks, low_risks = count_risks(
            risks
        )


        print(
            f"✓ Risks - High: {high_risks}, "
            f"Medium: {medium_risks}, "
            f"Low: {low_risks}"
        )


        # ====================================================
        # 13. SAVE HISTORY
        # ====================================================

        try:

            save_scan(
                security_score,
                high_risks,
                medium_risks,
                low_risks
            )

            print(
                "✓ Scan history saved"
            )

        except Exception as e:

            print(
                "Scan history error:",
                e
            )


        # ====================================================
        # 14. CLOUD REPORT
        # ====================================================

        print(
            "✓ Opening Cloud Security Report"
        )

        print(
            "========================================"
        )


        return render_template(

            "scan_results.html",

            score=security_score,

            status=security_status,

            dashboard_stats=dashboard_stats,

            risks=risks,

            alerts=alerts,

            advisor_result=advisor_result,

            compliance_report=compliance_report,

            system_info=system_info,

            iam_result=iam_result,

            ec2_result=ec2_result,

            s3_result=s3_result,

            sg_result=sg_result,

            scan_history=scan_history
        )


    except Exception as e:

        # ----------------------------------------------------
        # IMPORTANT:
        # Do not silently redirect to dashboard.
        # Show the error in the terminal and report page.
        # ----------------------------------------------------

        print()
        print("========================================")
        print("CLOUD SCAN ERROR")
        print("========================================")
        print(
            "Error Type:",
            type(e).__name__
        )
        print(
            "Error:",
            str(e)
        )
        print("========================================")
        print()


        return render_template(

            "scan_results.html",

            score=security_score,

            status="Scan Error",

            dashboard_stats={
                "iam_users": 0,
                "ec2_instances": 0,
                "s3_buckets": 0,
                "security_groups": 0
            },

            risks=[{
                "level": "High",
                "title": "Cloud Scan Error",
                "description": str(e)
            }],

            alerts=[],

            advisor_result=[],

            compliance_report=[],

            system_info=system_info,

            iam_result=iam_result,

            ec2_result=ec2_result,

            s3_result=s3_result,

            sg_result=sg_result,

            scan_history=scan_history
        )


# ============================================================
# DEVICE SECURITY SCAN
# ============================================================

@app.route("/device-scan")
def device_scan():

    global device_results
    global device_security_score
    global device_high_risks
    global device_medium_risks
    global device_low_risks
    global device_security_status
    global device_recommendations


    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    try:

        print()
        print("========================================")
        print("CyberGuardX Device Security Scan")
        print("========================================")


        # ====================================================
        # DEVICE SCANNER
        # ====================================================

        scanner = DeviceScanner()

        device_results = scanner.scan()


        if device_results is None:
            device_results = []


        print(
            f"✓ Device scan completed: "
            f"{len(device_results)} findings"
        )


        # ====================================================
        # COUNT RISKS
        # ====================================================

        (
            device_high_risks,
            device_medium_risks,
            device_low_risks
        ) = count_risks(
            device_results
        )


        # ====================================================
        # DEVICE SCORE
        # ====================================================

        device_security_score = calculate_device_score(

            device_high_risks,

            device_medium_risks,

            device_low_risks
        )


        # ====================================================
        # DEVICE STATUS
        # ====================================================

        device_security_status = get_device_status(
            device_security_score
        )


        # ====================================================
        # RECOMMENDATIONS
        # ====================================================

        device_recommendations = generate_device_recommendations(

            device_high_risks,

            device_medium_risks,

            device_low_risks
        )


        print(
            f"✓ Device Security Score: "
            f"{device_security_score}/100"
        )

        print(
            "========================================"
        )


        # ====================================================
        # DEVICE REPORT
        # ====================================================

        return render_template(

            "device_results.html",

            device_results=device_results,

            high_risks=device_high_risks,

            medium_risks=device_medium_risks,

            low_risks=device_low_risks,

            device_score=device_security_score,

            security_status=device_security_status,

            recommendations=device_recommendations
        )


    except Exception as e:

        print()
        print("========================================")
        print("DEVICE SCAN ERROR")
        print("========================================")
        print(
            "Error Type:",
            type(e).__name__
        )
        print(
            "Error:",
            str(e)
        )
        print("========================================")
        print()


        device_results = [{
            "category": "Scanner",
            "finding": "Device Scan Error",
            "details": str(e),
            "risk": "High"
        }]

        device_high_risks = 1
        device_medium_risks = 0
        device_low_risks = 0

        device_security_score = 85

        device_security_status = "Scan Error"

        device_recommendations = [
            "Review the device scanner error.",
            "Restart the application and run the device scan again."
        ]


        return render_template(

            "device_results.html",

            device_results=device_results,

            high_risks=device_high_risks,

            medium_risks=device_medium_risks,

            low_risks=device_low_risks,

            device_score=device_security_score,

            security_status=device_security_status,

            recommendations=device_recommendations
        )


# ============================================================
# DOWNLOAD SECURITY REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("login")
        )


    report_type = request.args.get(
        "type",
        "cloud"
    ).lower()


    # ========================================================
    # CLOUD PDF
    # ========================================================

    if report_type == "cloud":

        report_data = {

            "report_type":
                "Cloud Security Assessment",

            "security_score":
                security_score,

            "security_status":
                get_security_status(
                    security_score
                ),

            "system_info":
                system_info,

            "iam_result":
                iam_result,

            "ec2_result":
                ec2_result,

            "s3_result":
                s3_result,

            "sg_result":
                sg_result,

            "risks":
                risks,

            "alerts":
                alerts,

            "advisor_result":
                advisor_result,

            "compliance_report":
                compliance_report,

            "scan_history":
                scan_history
        }


        try:

            return generate_pdf(
                report_data
            )

        except Exception as e:

            print(
                "Cloud PDF generation error:",
                e
            )

            flash(
                f"Unable to generate cloud PDF: {e}",
                "error"
            )

            return redirect(
                url_for("scan")
            )


    # ========================================================
    # DEVICE PDF
    # ========================================================

    elif report_type == "device":

        report_data = {

            "report_type":
                "Device Security Assessment",

            "security_score":
                device_security_score,

            "security_status":
                device_security_status,

            "device_results":
                device_results,

            "high_risks":
                device_high_risks,

            "medium_risks":
                device_medium_risks,

            "low_risks":
                device_low_risks,

            "recommendations":
                device_recommendations
        }


        try:

            return generate_pdf(
                report_data
            )

        except Exception as e:

            print(
                "Device PDF generation error:",
                e
            )

            flash(
                f"Unable to generate device PDF: {e}",
                "error"
            )

            return redirect(
                url_for("device_scan")
            )


    # ========================================================
    # INVALID TYPE
    # ========================================================

    flash(
        "Invalid report type.",
        "error"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested CyberGuardX page does not exist.</p>
    """, 404


# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    print(
        "Internal Server Error:",
        error
    )

    return """
    <h1>500 - Internal Server Error</h1>
    <p>CyberGuardX encountered an unexpected error.</p>
    <p>Check the terminal for details.</p>
    """, 500


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print()
    print("==========================================")
    print("        CyberGuardX is starting...")
    print("==========================================")
    print()
    print("Dashboard:")
    print("http://127.0.0.1:5000")
    print()
    print("First visit:")
    print("Create Account → Sign In → Dashboard")
    print()
    print("Cloud Scan:")
    print("Dashboard → Cloud Scan → Cloud Security Report")
    print()
    print("Device Scan:")
    print("Dashboard → Device Scan → Device Security Report")
    print()
    print("==========================================")
    print()


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