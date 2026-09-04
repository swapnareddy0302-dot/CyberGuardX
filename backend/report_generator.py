from io import BytesIO
from datetime import datetime

from flask import send_file

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ============================================================
# HELPERS
# ============================================================

def get_value(
    item,
    *keys,
    default=""
):

    if isinstance(item, dict):

        for key in keys:

            if (
                key in item
                and item[key] not in (
                    None,
                    ""
                )
            ):

                return str(
                    item[key]
                )

    return default


def get_risk(item):

    return get_value(
        item,
        "level",
        "risk",
        "severity",
        default="Low"
    ).title()


def safe_text(value):

    if value is None:
        return ""

    return str(value)


def make_paragraph(
    text,
    style
):

    text = safe_text(
        text
    )

    text = (
        text
        .replace(
            "&",
            "&amp;"
        )
        .replace(
            "<",
            "&lt;"
        )
        .replace(
            ">",
            "&gt;"
        )
    )

    return Paragraph(
        text,
        style
    )


# ============================================================
# PDF GENERATOR
# ============================================================

def generate_pdf(report_data):

    """
    Generate CyberGuardX PDF.

    IMPORTANT:
    This function accepts ONE argument:
    report_data dictionary.
    """

    if not isinstance(
        report_data,
        dict
    ):

        report_data = {}


    buffer = BytesIO()


    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=
            16 * mm,

        leftMargin=
            16 * mm,

        topMargin=
            16 * mm,

        bottomMargin=
            16 * mm,

        title=
            "CyberGuardX Security Assessment Report",

        author=
            "CyberGuardX"
    )


    styles = (
        getSampleStyleSheet()
    )


    # ========================================================
    # STYLES
    # ========================================================

    title_style = ParagraphStyle(

        "CyberTitle",

        parent=
            styles["Title"],

        fontName=
            "Helvetica-Bold",

        fontSize=
            22,

        leading=
            27,

        alignment=
            TA_CENTER,

        textColor=
            colors.HexColor(
                "#123B75"
            ),

        spaceAfter=
            8
    )


    subtitle_style = ParagraphStyle(

        "CyberSubtitle",

        parent=
            styles["Normal"],

        fontName=
            "Helvetica",

        fontSize=
            9,

        leading=
            13,

        alignment=
            TA_CENTER,

        textColor=
            colors.HexColor(
                "#5B6B82"
            ),

        spaceAfter=
            14
    )


    section_style = ParagraphStyle(

        "CyberSection",

        parent=
            styles["Heading2"],

        fontName=
            "Helvetica-Bold",

        fontSize=
            14,

        leading=
            18,

        textColor=
            colors.HexColor(
                "#123B75"
            ),

        spaceBefore=
            10,

        spaceAfter=
            8
    )


    normal_style = ParagraphStyle(

        "CyberNormal",

        parent=
            styles["Normal"],

        fontName=
            "Helvetica",

        fontSize=
            8.5,

        leading=
            12,

        textColor=
            colors.HexColor(
                "#27364A"
            ),

        spaceAfter=
            5
    )


    small_style = ParagraphStyle(

        "CyberSmall",

        parent=
            normal_style,

        fontSize=
            7.2,

        leading=
            9.5
    )


    story = []


    # ========================================================
    # BASIC DATA
    # ========================================================

    score = int(
        report_data.get(
            "score",
            0
        )
        or 0
    )


    status = report_data.get(
        "status",
        "Not Scanned"
    )


    username = report_data.get(
        "username",
        "User"
    )


    report_type = report_data.get(
        "report_type",
        "Security Assessment"
    )


    # ========================================================
    # TITLE
    # ========================================================

    story.append(

        Paragraph(
            "CyberGuardX",
            title_style
        )
    )


    story.append(

        Paragraph(
            report_type,
            subtitle_style
        )
    )


    story.append(

        Paragraph(
            "Cloud & Device Security Intelligence",
            subtitle_style
        )
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    summary_data = [

        [
            make_paragraph(
                "REPORT TYPE",
                small_style
            ),

            make_paragraph(
                "SECURITY SCORE",
                small_style
            ),

            make_paragraph(
                "STATUS",
                small_style
            )
        ],

        [
            make_paragraph(
                report_type,
                normal_style
            ),

            make_paragraph(
                f"{score}/100",
                normal_style
            ),

            make_paragraph(
                status,
                normal_style
            )
        ],

        [
            make_paragraph(
                "USER",
                small_style
            ),

            make_paragraph(
                "GENERATED",
                small_style
            ),

            make_paragraph(
                "DATE",
                small_style
            )
        ],

        [
            make_paragraph(
                username,
                normal_style
            ),

            make_paragraph(
                datetime.now().strftime(
                    "%I:%M %p"
                ),
                normal_style
            ),

            make_paragraph(
                datetime.now().strftime(
                    "%d-%m-%Y"
                ),
                normal_style
            )
        ]
    ]


    summary_table = Table(

        summary_data,

        colWidths=[
            61 * mm,
            61 * mm,
            61 * mm
        ]
    )


    summary_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor(
                    "#F3F7FC"
                )
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor(
                    "#D5E0EE"
                )
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )


    story.append(
        summary_table
    )

    story.append(
        Spacer(
            1,
            10
        )
    )


    # ========================================================
    # SYSTEM INFORMATION
    # ========================================================

    story.append(

        Paragraph(
            "1. System Information",
            section_style
        )
    )


    system_info = (
        report_data.get(
            "system_info",
            {}
        )
        or {}
    )


    system_rows = [

        [
            make_paragraph(
                "PROPERTY",
                small_style
            ),

            make_paragraph(
                "VALUE",
                small_style
            )
        ]
    ]


    if isinstance(
        system_info,
        dict
    ) and system_info:

        for key, value in system_info.items():

            system_rows.append([

                make_paragraph(
                    str(key)
                    .replace(
                        "_",
                        " "
                    )
                    .title(),

                    normal_style
                ),

                make_paragraph(
                    value,
                    normal_style
                )
            ])

    else:

        system_rows.append([

            make_paragraph(
                "Information",
                normal_style
            ),

            make_paragraph(
                "No system information was available.",
                normal_style
            )
        ])


    system_table = Table(

        system_rows,

        colWidths=[
            60 * mm,
            124 * mm
        ],

        repeatRows=1
    )


    system_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#123B75"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.35,
                colors.HexColor(
                    "#D5E0EE"
                )
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor(
                        "#F7FAFD"
                    )
                ]
            )
        ])
    )


    story.append(
        system_table
    )


    # ========================================================
    # CLOUD OVERVIEW
    # ========================================================

    cloud_resources = [

        (
            "IAM Users",
            len(
                report_data.get(
                    "iam_result",
                    []
                )
                or []
            )
        ),

        (
            "EC2 Instances",
            len(
                report_data.get(
                    "ec2_result",
                    []
                )
                or []
            )
        ),

        (
            "S3 Buckets",
            len(
                report_data.get(
                    "s3_result",
                    []
                )
                or []
            )
        ),

        (
            "Security Groups",
            len(
                report_data.get(
                    "sg_result",
                    []
                )
                or []
            )
        )
    ]


    if any(
        value > 0
        for _, value in cloud_resources
    ):

        story.append(

            Paragraph(
                "2. Cloud Infrastructure Overview",
                section_style
            )
        )


        overview_rows = [

            [
                make_paragraph(
                    "RESOURCE",
                    small_style
                ),

                make_paragraph(
                    "COUNT",
                    small_style
                )
            ]
        ]


        for name, value in cloud_resources:

            overview_rows.append([

                make_paragraph(
                    name,
                    normal_style
                ),

                make_paragraph(
                    value,
                    normal_style
                )
            ])


        overview_table = Table(

            overview_rows,

            colWidths=[
                130 * mm,
                54 * mm
            ],

            repeatRows=1
        )


        overview_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "CENTER"
                )
            ])
        )


        story.append(
            overview_table
        )


    # ========================================================
    # RISK FINDINGS
    # ========================================================

    risks = (
        report_data.get(
            "risks",
            []
        )
        or []
    )


    if risks:

        story.append(

            Paragraph(
                "3. Risk Findings",
                section_style
            )
        )


        finding_rows = [

            [
                make_paragraph(
                    "#",
                    small_style
                ),

                make_paragraph(
                    "LEVEL",
                    small_style
                ),

                make_paragraph(
                    "FINDING",
                    small_style
                ),

                make_paragraph(
                    "DETAILS",
                    small_style
                )
            ]
        ]


        for index, item in enumerate(
            risks,
            1
        ):

            finding_rows.append([

                make_paragraph(
                    index,
                    small_style
                ),

                make_paragraph(
                    get_risk(item),
                    small_style
                ),

                make_paragraph(

                    get_value(
                        item,
                        "title",
                        "finding",
                        "issue",
                        default=
                            "Security Finding"
                    ),

                    small_style
                ),

                make_paragraph(

                    get_value(
                        item,
                        "description",
                        "details",
                        "message",
                        default=
                            "Review this finding."
                    ),

                    small_style
                )
            ])


        finding_table = Table(

            finding_rows,

            colWidths=[
                10 * mm,
                25 * mm,
                50 * mm,
                99 * mm
            ],

            repeatRows=1
        )


        finding_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(
            finding_table
        )


    # ========================================================
    # RESOURCE TABLES
    # ========================================================

    resources = [

        (
            "4. IAM Security Scan",
            report_data.get(
                "iam_result",
                []
            )
            or []
        ),

        (
            "5. EC2 Security Scan",
            report_data.get(
                "ec2_result",
                []
            )
            or []
        ),

        (
            "6. S3 Bucket Security",
            report_data.get(
                "s3_result",
                []
            )
            or []
        ),

        (
            "7. Security Group Analysis",
            report_data.get(
                "sg_result",
                []
            )
            or []
        )
    ]


    for heading, items in resources:

        if not items:
            continue


        story.append(

            Paragraph(
                heading,
                section_style
            )
        )


        if not isinstance(
            items[0],
            dict
        ):

            story.append(

                make_paragraph(
                    str(items),
                    normal_style
                )
            )

            continue


        keys = list(
            items[0].keys()
        )


        rows = [

            [
                make_paragraph(
                    str(key)
                    .replace(
                        "_",
                        " "
                    )
                    .upper(),

                    small_style
                )

                for key in keys
            ]
        ]


        for item in items:

            rows.append([

                make_paragraph(
                    item.get(
                        key,
                        ""
                    ),
                    small_style
                )

                for key in keys
            ])


        available_width = (
            184 * mm
        )


        column_width = (
            available_width
            / max(
                len(keys),
                1
            )
        )


        resource_table = Table(

            rows,

            colWidths=[
                column_width
            ] * len(keys),

            repeatRows=1
        )


        resource_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.25,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor(
                            "#F7FAFD"
                        )
                    ]
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )
            ])
        )


        story.append(
            resource_table
        )


    # ========================================================
    # ALERTS
    # ========================================================

    alerts = (
        report_data.get(
            "alerts",
            []
        )
        or []
    )


    if alerts:

        story.append(
            PageBreak()
        )


        story.append(

            Paragraph(
                "8. Security Alerts Center",
                section_style
            )
        )


        alert_rows = [

            [
                make_paragraph(
                    "ALERT",
                    small_style
                ),

                make_paragraph(
                    "SEVERITY",
                    small_style
                ),

                make_paragraph(
                    "DETAILS",
                    small_style
                )
            ]
        ]


        for item in alerts:

            alert_rows.append([

                make_paragraph(
                    get_value(
                        item,
                        "title",
                        "finding",
                        "alert",
                        default=
                            "Security Alert"
                    ),
                    small_style
                ),

                make_paragraph(
                    get_risk(item),
                    small_style
                ),

                make_paragraph(
                    get_value(
                        item,
                        "message",
                        "details",
                        "description",
                        default=
                            "Security event detected."
                    ),
                    small_style
                )
            ])


        alert_table = Table(

            alert_rows,

            colWidths=[
                55 * mm,
                30 * mm,
                99 * mm
            ],

            repeatRows=1
        )


        alert_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(
            alert_table
        )


    # ========================================================
    # SECURITY ADVISOR
    # ========================================================

    advisor = (
        report_data.get(
            "advisor_result",
            []
        )
        or []
    )


    if advisor:

        story.append(

            Paragraph(
                "9. CyberGuardX Security Advisor",
                section_style
            )
        )


        advisor_rows = [

            [
                make_paragraph(
                    "RECOMMENDATION",
                    small_style
                ),

                make_paragraph(
                    "ACTION",
                    small_style
                )
            ]
        ]


        if isinstance(
            advisor,
            dict
        ):

            for key, value in advisor.items():

                advisor_rows.append([

                    make_paragraph(
                        str(key)
                        .replace(
                            "_",
                            " "
                        )
                        .title(),

                        small_style
                    ),

                    make_paragraph(
                        value,
                        small_style
                    )
                ])

        else:

            for index, item in enumerate(
                advisor,
                1
            ):

                if isinstance(
                    item,
                    dict
                ):

                    text = get_value(
                        item,
                        "recommendation",
                        "advice",
                        "message",
                        default=str(item)
                    )

                else:

                    text = str(item)


                advisor_rows.append([

                    make_paragraph(
                        f"Recommendation {index}",
                        small_style
                    ),

                    make_paragraph(
                        text,
                        small_style
                    )
                ])


        advisor_table = Table(

            advisor_rows,

            colWidths=[
                55 * mm,
                129 * mm
            ],

            repeatRows=1
        )


        advisor_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(
            advisor_table
        )


    # ========================================================
    # COMPLIANCE
    # ========================================================

    compliance = (
        report_data.get(
            "compliance_report",
            []
        )
        or []
    )


    if compliance:

        story.append(

            Paragraph(
                "10. Compliance Dashboard",
                section_style
            )
        )


        compliance_rows = [

            [
                make_paragraph(
                    "CONTROL",
                    small_style
                ),

                make_paragraph(
                    "STATUS / DETAILS",
                    small_style
                )
            ]
        ]


        for item in compliance:

            if isinstance(
                item,
                dict
            ):

                name = get_value(
                    item,
                    "control",
                    "name",
                    "title",
                    default=
                        "Security Control"
                )

                detail = get_value(
                    item,
                    "status",
                    "details",
                    "description",
                    default=
                        str(item)
                )

            else:

                name = "Security Control"

                detail = str(item)


            compliance_rows.append([

                make_paragraph(
                    name,
                    small_style
                ),

                make_paragraph(
                    detail,
                    small_style
                )
            ])


        compliance_table = Table(

            compliance_rows,

            colWidths=[
                60 * mm,
                124 * mm
            ],

            repeatRows=1
        )


        compliance_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(
            compliance_table
        )


    # ========================================================
    # DEVICE INFORMATION
    # ========================================================

    device_items = (
        report_data.get(
            "device_results",
            []
        )
        or []
    )


    if device_items:

        story.append(

            Paragraph(
                "11. Device Security Assessment",
                section_style
            )
        )


        story.append(

            make_paragraph(

                (
                    f"Device Score: "
                    f"{report_data.get('device_score', 0)}/100 | "
                    f"Status: "
                    f"{report_data.get('device_status', 'Not Scanned')} | "
                    f"High: "
                    f"{report_data.get('device_high_risks', 0)} | "
                    f"Medium: "
                    f"{report_data.get('device_medium_risks', 0)} | "
                    f"Low: "
                    f"{report_data.get('device_low_risks', 0)}"
                ),

                normal_style
            )
        )


        device_rows = [

            [
                make_paragraph(
                    "CATEGORY",
                    small_style
                ),

                make_paragraph(
                    "FINDING",
                    small_style
                ),

                make_paragraph(
                    "DETAILS",
                    small_style
                ),

                make_paragraph(
                    "RISK",
                    small_style
                )
            ]
        ]


        for item in device_items:

            device_rows.append([

                make_paragraph(
                    get_value(
                        item,
                        "category",
                        default="Unknown"
                    ),
                    small_style
                ),

                make_paragraph(
                    get_value(
                        item,
                        "finding",
                        default="Unknown"
                    ),
                    small_style
                ),

                make_paragraph(
                    get_value(
                        item,
                        "details",
                        default=
                            "No details available."
                    ),
                    small_style
                ),

                make_paragraph(
                    get_risk(item),
                    small_style
                )
            ])


        device_table = Table(

            device_rows,

            colWidths=[
                35 * mm,
                42 * mm,
                82 * mm,
                25 * mm
            ],

            repeatRows=1
        )


        device_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )


        story.append(
            device_table
        )


    # ========================================================
    # DEVICE RECOMMENDATIONS
    # ========================================================

    recommendations = (
        report_data.get(
            "device_recommendations",
            []
        )
        or []
    )


    if recommendations:

        story.append(

            Paragraph(
                "12. Device Security Recommendations",
                section_style
            )
        )


        for index, recommendation in enumerate(
            recommendations,
            1
        ):

            story.append(

                make_paragraph(

                    f"{index}. {recommendation}",

                    normal_style
                )
            )


    # ========================================================
    # SCAN HISTORY
    # ========================================================

    history = (
        report_data.get(
            "scan_history",
            []
        )
        or []
    )


    if history:

        story.append(

            Paragraph(
                "13. Scan History",
                section_style
            )
        )


        history_rows = [

            [
                make_paragraph(
                    "SCAN",
                    small_style
                ),

                make_paragraph(
                    "DATE",
                    small_style
                ),

                make_paragraph(
                    "SCORE",
                    small_style
                ),

                make_paragraph(
                    "STATUS",
                    small_style
                )
            ]
        ]


        for item in history:

            if isinstance(
                item,
                dict
            ):

                scan_name = get_value(
                    item,
                    "type",
                    "scan_type",
                    default=
                        "Cloud Security Scan"
                )

                date = get_value(
                    item,
                    "date",
                    "timestamp",
                    default=
                        "Recent"
                )

                hist_score = get_value(
                    item,
                    "score",
                    default="-"
                )

                hist_status = get_value(
                    item,
                    "status",
                    default=
                        "Completed"
                )

            else:

                scan_name = "Security Scan"

                date = str(item)

                hist_score = "-"

                hist_status = "Completed"


            history_rows.append([

                make_paragraph(
                    scan_name,
                    small_style
                ),

                make_paragraph(
                    date,
                    small_style
                ),

                make_paragraph(
                    hist_score,
                    small_style
                ),

                make_paragraph(
                    hist_status,
                    small_style
                )
            ])


        history_table = Table(

            history_rows,

            colWidths=[
                60 * mm,
                55 * mm,
                30 * mm,
                39 * mm
            ],

            repeatRows=1
        )


        history_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123B75"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor(
                        "#D5E0EE"
                    )
                )
            ])
        )


        story.append(
            history_table
        )


    # ========================================================
    # FOOTER
    # ========================================================

    story.append(
        Spacer(
            1,
            15
        )
    )


    story.append(

        Paragraph(

            "CyberGuardX · Cloud & Device Security Intelligence · Generated automatically",

            subtitle_style
        )
    )


    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story
    )


    buffer.seek(0)


    # ========================================================
    # SEND FILE
    # ========================================================

    if report_data.get(
        "report_type",
        ""
    ).lower().startswith(
        "device"
    ):

        filename = (
            "CyberGuardX_Device_Security_Report.pdf"
        )

    else:

        filename = (
            "CyberGuardX_Cloud_Security_Report.pdf"
        )


    return send_file(

        buffer,

        as_attachment=True,

        download_name=filename,

        mimetype=
            "application/pdf"
    )