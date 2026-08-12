from flask import (
    Flask,
    render_template,
    request,
    session,
    send_file
)

from detector import detect_phishing

from stats import load_stats

from history import (
    add_history,
    get_recent_history
)

# PDF imports
import io

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.secret_key = "cybershield-ai-secret-key"


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template(
        "home.html"
    )


# =========================================================
# SCANNER
# =========================================================

@app.route(
    "/scanner",
    methods=["GET", "POST"]
)
def scanner():

    result = None

    # =====================================================
    # POST SCAN
    # =====================================================

    if request.method == "POST":

        # -------------------------------------------------
        # GET URL
        # -------------------------------------------------

        url = request.form.get(
            "url",
            ""
        ).strip()


        # -------------------------------------------------
        # CHECK EMPTY URL
        # -------------------------------------------------

        if not url:

            return render_template(
                "scanner.html",
                error="Please enter a website URL."
            )


        # -------------------------------------------------
        # ADD HTTPS IF NEEDED
        # -------------------------------------------------

        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url


        # =================================================
        # DETECT PHISHING
        # =================================================

        (
            prediction,
            score,
            reasons,
            recommendation,
            google_status,
            google_threat_types,
            ai_probability

        ) = detect_phishing(url)


        # =================================================
        # RISK LEVEL
        # =================================================

        if score <= 2:

            risk_level = "LOW RISK"

        elif score <= 5:

            risk_level = "MEDIUM RISK"

        else:

            risk_level = "HIGH RISK"


        # =================================================
        # SAVE SCAN HISTORY
        # =================================================

        add_history(
            url,
            prediction,
            score
        )


        # =================================================
        # CREATE RESULT
        # =================================================

        result = {

            "url": url,

            "prediction": prediction,

            "score": score,

            "risk_level": risk_level,

            "reasons": reasons,

            "recommendation": recommendation,

            "google_status": google_status,

            "google_threat_types":
                google_threat_types,

            "ai_probability":
                ai_probability
        }


        # =================================================
        # SAVE LATEST SCAN
        # =================================================

        session["last_scan"] = result


    # =====================================================
    # DISPLAY SCANNER
    # =====================================================

    return render_template(
        "scanner.html",
        result=result
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    # -----------------------------------------------------
    # GET LIVE STATISTICS
    # -----------------------------------------------------

    stats = load_stats()


    # -----------------------------------------------------
    # GET SCAN HISTORY
    # -----------------------------------------------------

    history = get_recent_history()


    # -----------------------------------------------------
    # DISPLAY DASHBOARD
    # -----------------------------------------------------

    return render_template(
        "dashboard.html",
        stats=stats,
        history=history
    )


# =========================================================
# CASE STUDY
# =========================================================

@app.route("/case-study")
def case_study():

    return render_template(
        "case_study.html"
    )


# =========================================================
# ABOUT
# =========================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# =========================================================
# DOWNLOAD SECURITY REPORT
# =========================================================

@app.route("/download-report")
def download_report():

    # =====================================================
    # CHECK IF A SCAN EXISTS
    # =====================================================

    if "last_scan" not in session:

        return "Please scan a website first."


    # =====================================================
    # GET LAST SCAN
    # =====================================================

    scan = session["last_scan"]


    # =====================================================
    # GET SCAN DATA
    # =====================================================

    url = scan.get(
        "url",
        ""
    )

    prediction = scan.get(
        "prediction",
        "SAFE"
    )

    score = scan.get(
        "score",
        0
    )

    risk_level = scan.get(
        "risk_level",
        "LOW RISK"
    )

    reasons = scan.get(
        "reasons",
        []
    )

    recommendation = scan.get(
        "recommendation",
        "This website appears safe based on our current analysis."
    )

    google_status = scan.get(
        "google_status",
        "NO KNOWN THREATS"
    )

    google_threat_types = scan.get(
        "google_threat_types",
        []
    )

    ai_probability = scan.get(
        "ai_probability",
        0.0
    )


    # =====================================================
    # CREATE PDF IN MEMORY
    # =====================================================

    pdf_buffer = io.BytesIO()


    document = SimpleDocTemplate(

        pdf_buffer,

        pagesize=A4,

        rightMargin=40,

        leftMargin=40,

        topMargin=30,

        bottomMargin=25
    )


    # =====================================================
    # STYLES
    # =====================================================

    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(

        "TitleStyle",

        parent=styles["Title"],

        alignment=TA_CENTER,

        textColor=colors.HexColor(
            "#2864d7"
        ),

        fontSize=22,

        leading=25
    )


    heading_style = ParagraphStyle(

        "HeadingStyle",

        parent=styles["Heading2"],

        textColor=colors.HexColor(
            "#2864d7"
        ),

        fontSize=13,

        leading=15,

        spaceBefore=0,

        spaceAfter=6
    )


    normal_style = ParagraphStyle(

        "NormalStyle",

        parent=styles["BodyText"],

        fontSize=8,

        leading=10
    )


    footer_style = ParagraphStyle(

        "FooterStyle",

        parent=normal_style,

        fontSize=6.5,

        leading=8,

        textColor=colors.HexColor(
            "#555555"
        )
    )


    story = []


    # =====================================================
    # TITLE
    # =====================================================

    story.append(

        Paragraph(

            "CyberShield AI",

            title_style

        )

    )


    story.append(

        Paragraph(

            "AI-Powered Phishing Detection Platform",

            styles["Heading3"]

        )

    )


    story.append(
        Spacer(1, 10)
    )


    # =====================================================
    # REPORT DETAILS
    # =====================================================

    report_data = [

        [
            "Website",
            url
        ],

        [
            "Prediction",
            prediction
        ],

        [
            "Risk Score",
            f"{score} / 10"
        ],

        [
            "Risk Level",
            risk_level
        ]

    ]


    report_table = Table(

        report_data,

        colWidths=[
            140,
            350
        ]

    )


    report_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#e8eefc")
            ),

            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.lightgrey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )

        ])

    )


    story.append(
        report_table
    )


    story.append(
        Spacer(1, 12)
    )


    # =====================================================
    # SECURITY ASSESSMENT
    # =====================================================

    story.append(

        Paragraph(

            "Security Assessment",

            heading_style

        )

    )


    if prediction == "PHISHING":

        assessment = "PHISHING DETECTED"

        assessment_color = colors.HexColor(
            "#a51f1f"
        )

    else:

        assessment = "SAFE WEBSITE"

        assessment_color = colors.HexColor(
            "#14783a"
        )


    assessment_table = Table(

        [
            [
                assessment
            ]
        ],

        colWidths=[
            490
        ]

    )


    assessment_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                assessment_color
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, -1),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                15
            ),

            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                9
            )

        ])

    )


    story.append(
        assessment_table
    )


    story.append(
        Spacer(1, 10)
    )


    # =====================================================
    # RISK SCORE
    # =====================================================

    story.append(

        Paragraph(

            "Risk Score",

            heading_style

        )

    )


    risk_table = Table(

        [
            [
                f"{score} / 10",
                risk_level
            ]
        ],

        colWidths=[
            245,
            245
        ]

    )


    risk_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f0f3fa")
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                14
            ),

            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.lightgrey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                9
            )

        ])

    )


    story.append(
        risk_table
    )


    story.append(
        Spacer(1, 10)
    )


    # =====================================================
    # AI MODEL ANALYSIS
    # =====================================================

    story.append(

        Paragraph(

            "AI Model Analysis",

            heading_style

        )

    )


    ai_percentage = round(
        float(ai_probability) * 100,
        1
    )


    ai_text = (

        f"<b>AI Phishing Probability:</b> "
        f"{ai_percentage}%"

    )


    ai_table = Table(

        [
            [
                Paragraph(
                    ai_text,
                    normal_style
                )
            ]
        ],

        colWidths=[
            490
        ]

    )


    ai_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#eef2ff")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.HexColor("#2864d7")
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )

        ])

    )


    story.append(
        ai_table
    )


    story.append(
        Spacer(1, 10)
    )


    # =====================================================
    # SECURITY ANALYSIS
    # =====================================================

    story.append(

        Paragraph(

            "Rule-Based Security Analysis",

            heading_style

        )

    )


    if reasons:

        # Do not repeat the AI probability line here.

        filtered_reasons = [

            reason

            for reason in reasons

            if not str(reason).startswith(
                "AI model phishing probability:"
            )

        ]


        if filtered_reasons:

            for reason in filtered_reasons:

                story.append(

                    Paragraph(

                        "• " + str(reason),

                        normal_style

                    )

                )

        else:

            story.append(

                Paragraph(

                    "• No suspicious rule-based indicators detected.",

                    normal_style

                )

            )

    else:

        story.append(

            Paragraph(

                "• No suspicious indicators detected.",

                normal_style

            )

        )


    story.append(
        Spacer(1, 8)
    )


    # =====================================================
    # GOOGLE SAFE BROWSING
    # =====================================================

    story.append(

        Paragraph(

            "Google Safe Browsing",

            heading_style

        )

    )


    if google_status == "THREAT DETECTED":

        google_text = (

            "<b>⚠ KNOWN THREAT DETECTED</b><br/>"

            "Google Safe Browsing identified "

            "this website as a known threat."

        )


        if google_threat_types:

            google_text += (

                "<br/><b>Threat types:</b> "

                + ", ".join(
                    map(
                        str,
                        google_threat_types
                    )
                )

            )


        google_bg = colors.HexColor(
            "#ffd9d9"
        )

        google_border = colors.HexColor(
            "#c62828"
        )

    else:

        google_text = (

            "<b>✓ NO KNOWN THREATS</b><br/>"

            "Google Safe Browsing did not identify "

            "this URL as a known unsafe resource."

        )


        google_bg = colors.HexColor(
            "#d9f7e5"
        )

        google_border = colors.HexColor(
            "#14783a"
        )


    google_table = Table(

        [
            [
                Paragraph(
                    google_text,
                    normal_style
                )
            ]
        ],

        colWidths=[
            490
        ]

    )


    google_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                google_bg
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                google_border
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            )

        ])

    )


    story.append(
        google_table
    )


    story.append(
        Spacer(1, 10)
    )


    # =====================================================
    # SECURITY RECOMMENDATION
    # =====================================================

    story.append(

        Paragraph(

            "Security Recommendation",

            heading_style

        )

    )


    recommendation_table = Table(

        [
            [
                Paragraph(
                    str(recommendation),
                    normal_style
                )
            ]
        ],

        colWidths=[
            490
        ]

    )


    recommendation_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f0f3fa")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.HexColor("#2864d7")
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )

        ])

    )


    story.append(
        recommendation_table
    )


    story.append(
        Spacer(1, 15)
    )


    # =====================================================
    # DISCLAIMER
    # =====================================================

    story.append(

        Paragraph(

            "<b>Important:</b> This report is generated "
            "automatically using CyberShield AI's "
            "rule-based phishing detection engine, "
            "machine-learning model, and Google Safe "
            "Browsing. Results should be used as a "
            "security indicator and not as a guarantee "
            "that a website is completely safe or malicious.",

            footer_style

        )

    )


    # =====================================================
    # BUILD PDF
    # =====================================================

    document.build(
        story
    )


    # =====================================================
    # SEND PDF
    # =====================================================

    pdf_buffer.seek(0)


    return send_file(

        pdf_buffer,

        as_attachment=True,

        download_name="CyberShield_Security_Report.pdf",

        mimetype="application/pdf"

    )


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )