from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

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


from database import (
    create_user_table,
    get_db_connection
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cyberguardx_secret_key"
)


# ============================================================
# CREATE DATABASE TABLE
# ============================================================

create_user_table()


# ============================================================
# CLOUD DATA
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
# DEVICE DATA
# ============================================================

device_results = []

device_security_score = 0

device_security_status = "Not Scanned"

device_high_risks = 0

device_medium_risks = 0

device_low_risks = 0

device_recommendations = []


# ============================================================
# RISK HELPERS
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

    if value is None:

        return "Low"

    return str(
        value
    ).strip().title()


def count_risks(items):

    high = 0

    medium = 0

    low = 0

    for item in items or []:

        level = get_risk_level(
            item
        )

        if level == "High":

            high += 1

        elif level == "Medium":

            medium += 1

        else:

            low += 1

    return (
        high,
        medium,
        low
    )


def security_status_from_score(
    score
):

    if score >= 85:

        return "Excellent"

    elif score >= 70:

        return "Good"

    elif score >= 50:

        return "Needs Attention"

    return "Critical"


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
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


        if not username or not password:

            return render_template(
                "login.html",
                error=(
                    "Please enter "
                    "username and password."
                )
            )


        connection = get_db_connection()

        user = None

        try:

            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                """,
                (
                    username,
                )
            ).fetchone()

        finally:

            connection.close()


        if user is None:

            return render_template(
                "login.html",
                error=(
                    "Username not found. "
                    "Please register first."
                )
            )


        if check_password_hash(
            user["password"],
            password
        ):

            session["logged_in"] = True

            session["user_id"] = user["id"]

            session["username"] = (
                user["username"]
            )

            session["email"] = (
                user["email"]
            )

            return redirect("/")


        return render_template(
            "login.html",
            error="Wrong password."
        )


    return render_template(
        "login.html",
        error=None
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=[
        "GET",
        "POST"
    ]
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
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if (
            not username
            or not email
            or not password
            or not confirm_password
        ):

            return render_template(
                "register.html",
                error=(
                    "Please fill in all fields."
                )
            )


        if len(password) < 6:

            return render_template(
                "register.html",
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
            )


        if password != confirm_password:

            return render_template(
                "register.html",
                error=(
                    "Passwords do not match."
                )
            )


        connection = get_db_connection()


        try:

            existing_username = (
                connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE username = ?
                    """,
                    (
                        username,
                    )
                ).fetchone()
            )


            if existing_username:

                return render_template(
                    "register.html",
                    error=(
                        "Username already exists. "
                        "Please sign in."
                    )
                )


            existing_email = (
                connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE email = ?
                    """,
                    (
                        email,
                    )
                ).fetchone()
            )


            if existing_email:

                return render_template(
                    "register.html",
                    error=(
                        "Email already exists. "
                        "Please sign in."
                    )
                )


            hashed_password = (
                generate_password_hash(
                    password
                )
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


            flash(
                "Registration successful! Please login.",
                "success"
            )


            return redirect(
                "/login"
            )


        except Exception as error:

            connection.rollback()

            print(
                "DATABASE ERROR:",
                error
            )


            return render_template(
                "register.html",
                error=(
                    "Unable to create the account. "
                    "Please try again."
                )
            )


        finally:

            connection.close()


    return render_template(
        "register.html",
        error=None
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            "/register"
        )


    dashboard_stats = {

        "iam_users":
            len(iam_result),

        "ec2_instances":
            len(ec2_result),

        "s3_buckets":
            len(s3_result),

        "security_groups":
            len(sg_result)

    }


    return render_template(
        "dashboard.html",

        score=security_score,

        status=security_status,

        dashboard_stats=dashboard_stats,

        device_security_score=(
            device_security_score
        ),

        device_security_status=(
            device_security_status
        ),

        scan_history=scan_history
    )


# ============================================================
# CLOUD SECURITY SCAN
# ============================================================

@app.route("/scan")
def scan():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            "/login"
        )


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


    print(
        "\n==================================="
    )

    print(
        "CYBERGUARDX CLOUD SCAN STARTED"
    )

    print(
        "===================================\n"
    )


    # SYSTEM INFORMATION

    system_info = (
        get_system_info()
    )


    # IAM

    iam_result = (
        IAMScanner().scan()
    )


    # EC2

    ec2_result = (
        EC2Scanner().scan()
    )


    # S3

    s3_result = (
        S3Scanner().scan()
    )


    # SECURITY GROUPS

    sg_result = (
        SecurityGroupScanner().scan()
    )


    print(
        "IAM RESULT:",
        iam_result
    )

    print(
        "EC2 RESULT:",
        ec2_result
    )

    print(
        "S3 RESULT:",
        s3_result
    )

    print(
        "SECURITY GROUP RESULT:",
        sg_result
    )


    # RISK ENGINE

    risk_result = (
        RiskEngine().calculate_score(
            iam_result,
            ec2_result,
            s3_result,
            sg_result
        )
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


    security_status = (
        risk_result.get(
            "status",
            security_status_from_score(
                security_score
            )
        )
    )


    # COMPLIANCE

    compliance_report = (
        ComplianceEngine()
        .generate_report(
            iam_result,
            ec2_result,
            s3_result,
            sg_result
        )
    )


    # ALERTS

    alerts = (
        AlertEngine()
        .generate_alerts(
            iam_result,
            ec2_result,
            s3_result,
            sg_result
        )
    )


    # SECURITY ADVISOR

    advisor_result = (
        SecurityAdvisor()
        .generate_advice(
            iam_result,
            ec2_result,
            s3_result,
            sg_result
        )
    )


    # RISK COUNTS

    (
        high_risks,
        medium_risks,
        low_risks
    ) = count_risks(
        risks
    )


    # SAVE HISTORY

    try:

        save_scan(
            security_score,
            security_status,
            high_risks,
            medium_risks,
            low_risks
        )

        scan_history = (
            get_history()
        )

    except Exception as error:

        print(
            "HISTORY ERROR:",
            error
        )

        scan_history = []


    dashboard_stats = {

        "iam_users":
            len(iam_result),

        "ec2_instances":
            len(ec2_result),

        "s3_buckets":
            len(s3_result),

        "security_groups":
            len(sg_result)

    }


    print(
        "\n==================================="
    )

    print(
        "CLOUD SCAN COMPLETE"
    )

    print(
        "SCORE:",
        security_score
    )

    print(
        "STATUS:",
        security_status
    )

    print(
        "===================================\n"
    )


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

        compliance_report=(
            compliance_report
        ),

        advisor_result=(
            advisor_result
        ),

        scan_history=scan_history,

        device_results=device_results,

        device_security_score=(
            device_security_score
        ),

        device_security_status=(
            device_security_status
        ),

        device_high_risks=(
            device_high_risks
        ),

        device_medium_risks=(
            device_medium_risks
        ),

        device_low_risks=(
            device_low_risks
        ),

        device_recommendations=(
            device_recommendations
        )
    )


# ============================================================
# DEVICE SECURITY SCAN
# ============================================================

@app.route("/device-scan")
def device_scan():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            "/login"
        )


    global device_results
    global device_security_score
    global device_security_status
    global device_high_risks
    global device_medium_risks
    global device_low_risks
    global device_recommendations


    print(
        "\n==================================="
    )

    print(
        "CYBERGUARDX DEVICE SCAN STARTED"
    )

    print(
        "===================================\n"
    )


    device_results = (
        DeviceScanner().scan()
    )


    (
        device_high_risks,
        device_medium_risks,
        device_low_risks
    ) = count_risks(
        device_results
    )


    # DEVICE SCORE

    device_security_score = 100


    device_security_score -= (
        device_high_risks * 15
    )


    device_security_score -= (
        device_medium_risks * 7
    )


    device_security_score -= (
        device_low_risks
    )


    if device_security_score < 0:

        device_security_score = 0


    device_security_status = (
        security_status_from_score(
            device_security_score
        )
    )


    # DEVICE RECOMMENDATIONS

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


    device_recommendations.append(
        "Keep the operating system and security software updated."
    )


    device_recommendations.append(
        "Disable unnecessary services and listening ports."
    )


    device_recommendations.append(
        "Use a firewall and avoid exposing unnecessary network services."
    )


    print(
        "\n==================================="
    )

    print(
        "DEVICE SCAN COMPLETE"
    )

    print(
        "SCORE:",
        device_security_score
    )

    print(
        "STATUS:",
        device_security_status
    )

    print(
        "===================================\n"
    )


    return render_template(

        "scan_results.html",

        scan_type="device",

        score=security_score,

        status=security_status,

        dashboard_stats={

            "iam_users":
                len(iam_result),

            "ec2_instances":
                len(ec2_result),

            "s3_buckets":
                len(s3_result),

            "security_groups":
                len(sg_result)

        },

        system_info=system_info,

        iam_result=iam_result,

        ec2_result=ec2_result,

        s3_result=s3_result,

        sg_result=sg_result,

        risks=risks,

        alerts=alerts,

        compliance_report=(
            compliance_report
        ),

        advisor_result=(
            advisor_result
        ),

        scan_history=scan_history,

        device_results=device_results,

        device_security_score=(
            device_security_score
        ),

        device_security_status=(
            device_security_status
        ),

        device_high_risks=(
            device_high_risks
        ),

        device_medium_risks=(
            device_medium_risks
        ),

        device_low_risks=(
            device_low_risks
        ),

        device_recommendations=(
            device_recommendations
        )
    )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

@app.route(
    "/download-report"
)
def download_report():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            "/login"
        )


    report_data = {

        "security_score":
            security_score,

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

        "advisor_result":
            advisor_result,

        "scan_history":
            scan_history

    }


    # Supports both your old
    # and newer report_generator.py.

    parameter_count = len(
        inspect.signature(
            generate_pdf
        ).parameters
    )


    if parameter_count == 1:

        return generate_pdf(
            report_data
        )


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


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()


    flash(
        "You have been logged out.",
        "success"
    )


    return redirect(
        "/login"
    )


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        error
    )

    return render_template(
        "login.html",
        error=(
            "Something went wrong "
            "on the server. Please try again."
        )
    ), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    print(
        "==================================="
    )

    print(
        "CyberGuardX is starting..."
    )

    print(
        "Open: http://127.0.0.1:5000"
    )

    print(
        "==================================="
    )


    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )


    app.run(

        host="0.0.0.0",

        port=port,

        debug=True

    )