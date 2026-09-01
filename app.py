from flask import Flask, render_template, request, redirect, session, flash

from backend.scanner.iam_scanner import IAMScanner
from backend.scanner.ec2_scanner import EC2Scanner
from backend.scanner.s3_scanner import S3Scanner
from backend.scanner.security_group_scanner import SecurityGroupScanner

from backend.risk_engine import RiskEngine
from backend.system_info import get_system_info
from backend.history_manager import save_scan, get_history
from backend.advisor import SecurityAdvisor
from backend.compliance import ComplianceEngine
from backend.alert_engine import AlertEngine
from backend.report_generator import generate_pdf
from backend.scanner.device_scanner import DeviceScanner
from database import create_user_table, get_db_connection
import random
from werkzeug.security import generate_password_hash, check_password_hash


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)

app.secret_key = "cyberguardx_secret_key"


# ==========================================
# CREATE USER DATABASE TABLE
# ==========================================

create_user_table()


# ==========================================
# GLOBAL STORAGE FOR SCAN DATA
# ==========================================

security_score = 0

system_info = {}

iam_result = []

ec2_result = []

s3_result = []

sg_result = []

advisor_result = {

    "status": "Waiting",

    "priority": "None",

    "time": "-",

    "recommendations": [

        "Run a security scan first."

    ]

}

scan_history = []


# ==========================================
# LOGIN
# ==========================================

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

        print("===================================")
        print("LOGIN ATTEMPT")
        print("USERNAME:", username)
        print("===================================")

        connection = get_db_connection()

        try:

            user = connection.execute(

                "SELECT * FROM users WHERE username = ?",

                (username,)

            ).fetchone()

        finally:

            connection.close()


        # USER DOES NOT EXIST

        if user is None:

            print("LOGIN FAILED: USER NOT FOUND")

            return render_template(

                "login.html",

                error="Username not found. Please register first."

            )


        print("USER FOUND:", user["username"])


        # PASSWORD CHECK

        if check_password_hash(

            user["password"],

            password

        ):

            print("LOGIN SUCCESS")

            session["logged_in"] = True

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            return redirect("/")


        else:

            print("LOGIN FAILED: WRONG PASSWORD")

            return render_template(

                "login.html",

                error="Wrong password."

            )


    return render_template(

        "login.html",

        error=None

    )


# ==========================================
# REGISTER
# ==========================================

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

        ).strip()


        password = request.form.get(

            "password",

            ""

        )


        print("===================================")
        print("REGISTER ATTEMPT")
        print("USERNAME:", username)
        print("EMAIL:", email)
        print("===================================")


        # CHECK EMPTY FIELDS

        if not username or not email or not password:

            return render_template(

                "register.html",

                error="Please fill in all fields."

            )


        # HASH PASSWORD

        hashed_password = generate_password_hash(

            password

        )


        connection = get_db_connection()


        try:

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


            print("USER REGISTERED SUCCESSFULLY")


            flash(

                "Registration successful! Please login.",

                "success"

            )


            return redirect("/login")


        except Exception as e:

            print("===================================")
            print("DATABASE ERROR")
            print(e)
            print("===================================")


            return render_template(

                "register.html",

                error="Username or email already exists."

            )


        finally:

            connection.close()


    return render_template(

        "register.html",

        error=None

    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    if not session.get("logged_in"):

        return redirect("/login")


    return render_template(

        "dashboard.html"

    )


# ==========================================
# RUN SECURITY SCAN
# ==========================================

@app.route("/scan")
def scan():

    if not session.get("logged_in"):

        return redirect("/login")


    global security_score
    global system_info
    global iam_result
    global ec2_result
    global s3_result
    global sg_result
    global advisor_result
    global scan_history


    print("===================================")
    print("SECURITY SCAN STARTED")
    print("===================================")


    # =====================================
    # SYSTEM INFORMATION
    # =====================================

    system_info = get_system_info()


    # =====================================
    # IAM SCAN
    # =====================================

    iam_result = IAMScanner().scan()

    print("IAM RESULT:", iam_result)


    # =====================================
    # EC2 SCAN
    # =====================================

    ec2_result = EC2Scanner().scan()

    print("EC2 RESULT:", ec2_result)


    # =====================================
    # S3 SCAN
    # =====================================

    s3_result = S3Scanner().scan()

    print("S3 RESULT:", s3_result)


    # =====================================
    # SECURITY GROUP SCAN
    # =====================================

    sg_result = SecurityGroupScanner().scan()

    print("SECURITY GROUP RESULT:", sg_result)


    # =====================================
    # DASHBOARD STATISTICS
    # =====================================

    dashboard_stats = {

        "iam_users": len(iam_result),

        "ec2_instances": len(ec2_result),

        "s3_buckets": len(s3_result),

        "security_groups": len(sg_result)

    }


    # =====================================
    # RISK ENGINE
    # =====================================

    engine = RiskEngine()


    risk_result = engine.calculate_score(

        iam_result,

        ec2_result,

        s3_result,

        sg_result

    )


    print("RISK RESULT:", risk_result)


    # =====================================
    # COMPLIANCE ENGINE
    # =====================================

    compliance = ComplianceEngine()


    compliance_report = compliance.generate_report(

        iam_result,

        ec2_result,

        s3_result,

        sg_result

    )


    # =====================================
    # ALERT ENGINE
    # =====================================

    alert_engine = AlertEngine()


    alerts = alert_engine.generate_alerts(

        iam_result,

        ec2_result,

        s3_result,

        sg_result

    )


    # =====================================
    # SECURITY ADVISOR
    # =====================================

    advisor = SecurityAdvisor()


    advisor_result = advisor.generate_advice(

        iam_result,

        ec2_result,

        s3_result,

        sg_result

    )


    print("ADVISOR RESULT:", advisor_result)


    # =====================================
    # SECURITY SCORE
    # =====================================

    security_score = risk_result["score"]


    # =====================================
    # COUNT RISKS
    # =====================================

    critical_risks = 0

    medium_risks = 0

    low_risks = 0


    for risk in risk_result["risks"]:


        if risk["level"] == "High":

            critical_risks += 1


        elif risk["level"] == "Medium":

            medium_risks += 1


        elif risk["level"] == "Low":

            low_risks += 1


    # =====================================
    # SAVE SCAN HISTORY
    # =====================================

    save_scan(

        security_score,

        risk_result["status"],

        critical_risks,

        medium_risks,

        low_risks

    )


    scan_history = get_history()


    # =====================================
    # DISPLAY RESULTS
    # =====================================

    return render_template(

        "index.html",

        score=security_score,

        status=risk_result["status"],

        risks=risk_result["risks"],

        system_info=system_info,

        iam_result=iam_result,

        ec2_result=ec2_result,

        s3_result=s3_result,

        sg_result=sg_result,

        dashboard_stats=dashboard_stats,

        risk_result=risk_result,

        scan_history=scan_history,

        advisor_result=advisor_result,

        compliance_report=compliance_report,

        alerts=alerts

    )
@app.route("/device-scan")
def device_scan():

    if not session.get("logged_in"):

        return redirect("/login")


    print("===================================")
    print("DEVICE SECURITY SCAN STARTED")
    print("===================================")


    device_scanner = DeviceScanner()

    device_results = device_scanner.scan()


    # =================================
    # RISK COUNTS
    # =================================

    high_risks = sum(

        1 for result in device_results

        if result["risk"] == "High"

    )


    medium_risks = sum(

        1 for result in device_results

        if result["risk"] == "Medium"

    )


    low_risks = sum(

        1 for result in device_results

        if result["risk"] == "Low"

    )


    # =================================
    # DEVICE SECURITY SCORE
    # =================================

    score = 100

    score -= high_risks * 15

    score -= medium_risks * 7

    score -= low_risks * 1


    if score < 0:

        score = 0


    # =================================
    # SECURITY STATUS
    # =================================

    if score >= 85:

        security_status = "Excellent"

    elif score >= 70:

        security_status = "Good"

    elif score >= 50:

        security_status = "Needs Attention"

    else:

        security_status = "High Risk"


    # =================================
    # SECURITY RECOMMENDATIONS
    # =================================

    recommendations = []


    if high_risks > 0:

        recommendations.append(

            "Review all high-risk findings immediately."

        )


    if medium_risks > 0:

        recommendations.append(

            "Investigate medium-risk findings and reduce unnecessary exposure."

        )


    if not recommendations:

        recommendations.append(

            "No major risks detected. Continue performing regular security scans."

        )


    recommendations.append(

        "Keep your operating system and security software updated."

    )


    recommendations.append(

        "Disable unnecessary services and listening ports."

    )


    # =================================
    # RENDER RESULTS
    # =================================

    return render_template(

        "device_results.html",

        device_results=device_results,

        high_risks=high_risks,

        medium_risks=medium_risks,

        low_risks=low_risks,

        device_score=score,

        security_status=security_status,

        recommendations=recommendations

    )
# ==========================================
# DOWNLOAD PDF REPORT
# ==========================================

@app.route("/download-report")
def download_report():

    if not session.get("logged_in"):

        return redirect("/login")


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


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()


    flash(

        "You have been logged out.",

        "success"

    )


    return redirect("/login")


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    print("===================================")
    print("CyberGuardX is starting...")
    print("Open: http://127.0.0.1:5000")
    print("===================================")


import os


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )