from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from xml.sax.saxutils import escape


def generate_report(
    url,
    prediction,
    score,
    risk_level,
    reasons,
    recommendation,
    google_status,
    google_threat_types,
    filename
):

    # =====================================================
    # PDF SETUP
    # =====================================================

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    # =====================================================
    # STYLES
    # =====================================================

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2563eb"),
        spaceAfter=5
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica-BoldOblique",
        fontSize=13,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.black,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#2563eb"),
        spaceBefore=10,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#222222")
    )

    # =====================================================
    # STATUS STYLE
    # =====================================================

    status_style = ParagraphStyle(
        "StatusStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.white
    )

    risk_score_style = ParagraphStyle(
        "RiskScoreStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        textColor=colors.black
    )

    risk_level_style = ParagraphStyle(
        "RiskLevelStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=20,
        alignment=TA_CENTER
    )

    disclaimer_style = ParagraphStyle(
        "DisclaimerStyle",
        parent=normal_style,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555")
    )

    story = []

    # =====================================================
    # HEADER
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
            subtitle_style
        )
    )

    # =====================================================
    # BASIC INFORMATION
    # =====================================================

    prediction_text = str(prediction).upper()
    risk_level_text = str(risk_level).upper()

    info_data = [
        [
            Paragraph("<b>Website</b>", normal_style),
            Paragraph(
                escape(str(url)),
                normal_style
            )
        ],
        [
            Paragraph("<b>Prediction</b>", normal_style),
            Paragraph(
                escape(prediction_text),
                normal_style
            )
        ],
        [
            Paragraph("<b>Risk Score</b>", normal_style),
            Paragraph(
                f"{score} / 10",
                normal_style
            )
        ],
        [
            Paragraph("<b>Risk Level</b>", normal_style),
            Paragraph(
                escape(risk_level_text),
                normal_style
            )
        ]
    ]

    info_table = Table(
        info_data,
        colWidths=[
            48 * mm,
            117 * mm
        ]
    )

    info_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#cbd5e1")
            ),

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#e8eefb")
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
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

    story.append(info_table)

    story.append(
        Spacer(1, 18)
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

    # =====================================================
    # STATUS
    # =====================================================

    if prediction_text == "PHISHING":

        status_text = "PHISHING DETECTED"

        status_background = colors.HexColor("#b91c1c")

    else:

        status_text = "SAFE WEBSITE"

        status_background = colors.HexColor("#15803d")

    # =====================================================
    # STATUS BOX
    # =====================================================

    status = Table(
        [
            [
                Paragraph(
                    status_text,
                    status_style
                )
            ]
        ],
        colWidths=[
            165 * mm
        ],
        rowHeights=[
            16 * mm
        ]
    )

status = Table(
    [
        [
            Paragraph(
                status_text,
                status_style
            )
        ]
    ],
    colWidths=[
        165 * mm
    ]
)

status.setStyle(
    TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, -1),
            status_background
        ),

        (
            "BOX",
            (0, 0),
            (-1, -1),
            1,
            status_background
        ),

        (
            "ALIGN",
            (0, 0),
            (-1, -1),
            "CENTER"
        ),

        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "MIDDLE"
        ),

        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            10
        ),

        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            10
        ),

        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            8
        ),

        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            8
        )
    ])
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

    if risk_level_text == "LOW RISK":

        risk_color = colors.HexColor("#15803d")

    elif risk_level_text == "MEDIUM RISK":

        risk_color = colors.HexColor("#f59e0b")

    else:

        risk_color = colors.HexColor("#dc2626")

    risk_level_colored_style = ParagraphStyle(
        "RiskLevelColored",
        parent=risk_level_style,
        textColor=risk_color
    )

    risk_table = Table(
        [
            [
                Paragraph(
                    f"{score} / 10",
                    risk_score_style
                ),

                Paragraph(
                    risk_level_text,
                    risk_level_colored_style
                )
            ]
        ],
        colWidths=[
            82.5 * mm,
            82.5 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f1f5f9")
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#cbd5e1")
            ),

            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(risk_table)

    story.append(
        Spacer(1, 14)
    )

    # =====================================================
    # SECURITY ANALYSIS
    # =====================================================

    story.append(
        Paragraph(
            "Security Analysis",
            heading_style
        )
    )

    if reasons:

        for reason in reasons:

            story.append(
                Paragraph(
                    "• " + escape(str(reason)),
                    normal_style
                )
            )

            story.append(
                Spacer(1, 3)
            )

    else:

        story.append(
            Paragraph(
                "• No suspicious indicators detected.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 10)
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

    if google_threat_types:

        threat_lines = []

        for threat in google_threat_types:

            threat_lines.append(
                "• " + escape(str(threat))
            )

        threat_text = "<br/>".join(
            threat_lines
        )

        google_data = [
            [
                Paragraph(
                    "<b>⚠ KNOWN THREAT DETECTED</b>",
                    normal_style
                )
            ],

            [
                Paragraph(
                    "Google Safe Browsing identified this URL as an unsafe resource.",
                    normal_style
                )
            ],

            [
                Paragraph(
                    "<b>Threat types:</b><br/>"
                    + threat_text,
                    normal_style
                )
            ]
        ]

        google_table = Table(
            google_data,
            colWidths=[
                165 * mm
            ]
        )

        google_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#fee2e2")
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    colors.HexColor("#dc2626")
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ])
        )

    else:

        google_data = [
            [
                Paragraph(
                    "<b>✓ NO KNOWN THREATS</b>",
                    normal_style
                )
            ],

            [
                Paragraph(
                    "Google Safe Browsing did not identify this URL as a known unsafe resource.",
                    normal_style
                )
            ]
        ]

        google_table = Table(
            google_data,
            colWidths=[
                165 * mm
            ]
        )

        google_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#dcfce7")
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    colors.HexColor("#15803d")
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ])
        )

    story.append(google_table)

    story.append(
        Spacer(1, 14)
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
                    escape(str(recommendation)),
                    normal_style
                )
            ]
        ],
        colWidths=[
            165 * mm
        ]
    )

    recommendation_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f1f5f9")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.HexColor("#2563eb")
            ),

            (
                "LINEBEFORE",
                (0, 0),
                (0, -1),
                4,
                colors.HexColor("#2563eb")
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )
        ])
    )

    story.append(
        recommendation_table
    )

    story.append(
        Spacer(1, 20)
    )

    # =====================================================
    # DISCLAIMER
    # =====================================================

    story.append(
        Paragraph(
            "<b>Important:</b> This report is generated automatically "
            "using CyberShield AI's rule-based phishing detection engine "
            "and Google Safe Browsing. Results should be used as a "
            "security indicator and not as a guarantee that a website "
            "is completely safe or malicious.",
            disclaimer_style
        )
    )

    # =====================================================
    # CREATE PDF
    # =====================================================

    doc.build(story)