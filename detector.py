import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
import os

from ai_model import predict_with_ai


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

GOOGLE_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY"
)


SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/"
    "threatMatches:find"
)


# =========================================================
# GOOGLE SAFE BROWSING
# =========================================================

def check_google_safe_browsing(url):

    if not GOOGLE_API_KEY:

        print(
            "ERROR: Google Safe Browsing API key not found."
        )

        return False, []


    try:

        response = requests.post(

            SAFE_BROWSING_URL,

            params={
                "key": GOOGLE_API_KEY
            },

            json={

                "client": {

                    "clientId": "CyberShieldAI",

                    "clientVersion": "1.0"

                },

                "threatInfo": {

                    "threatTypes": [

                        "MALWARE",

                        "SOCIAL_ENGINEERING",

                        "UNWANTED_SOFTWARE",

                        "POTENTIALLY_HARMFUL_APPLICATION"

                    ],

                    "platformTypes": [

                        "ANY_PLATFORM"

                    ],

                    "threatEntryTypes": [

                        "URL"

                    ],

                    "threatEntries": [

                        {
                            "url": url
                        }

                    ]

                }

            },

            timeout=10

        )


        print(
            "Google Safe Browsing status:",
            response.status_code
        )


        response.raise_for_status()


        data = response.json()


        threats = data.get(
            "matches",
            []
        )


        # =============================================
        # THREAT FOUND
        # =============================================

        if threats:

            threat_types = []


            for threat in threats:

                threat_type = threat.get(
                    "threatType"
                )


                if (
                    threat_type
                    and threat_type not in threat_types
                ):

                    threat_types.append(
                        threat_type
                    )


            print(
                "Google threat detected:",
                threat_types
            )


            return True, threat_types


        # =============================================
        # NO THREAT
        # =============================================

        print(
            "Google Safe Browsing: No threats found."
        )


        return False, []


    except requests.RequestException as e:

        print(
            "Google Safe Browsing API error:",
            e
        )

        return False, []


    except ValueError as e:

        print(
            "Google JSON error:",
            e
        )

        return False, []


# =========================================================
# PHISHING DETECTOR
# =========================================================

def detect_phishing(url):


    # =====================================================
    # VARIABLES
    # =====================================================

    reasons = []

    score = 0


    # =====================================================
    # PARSE URL
    # =====================================================

    parsed = urlparse(url)


    # =====================================================
    # AI / MACHINE LEARNING
    # =====================================================

    ai_prediction, ai_probability = predict_with_ai(url)


    print(
        "AI Prediction:",
        ai_prediction
    )


    print(
        "AI Phishing Probability:",
        round(ai_probability * 100, 2),
        "%"
    )


    # =====================================================
    # AI RESULT
    # =====================================================

    if ai_prediction is not None:

        ai_percentage = round(
            ai_probability * 100,
            2
        )


        reasons.append(
            f"AI model phishing probability: "
            f"{ai_percentage}%"
        )


        # ---------------------------------------------
        # HIGH AI CONFIDENCE
        # ---------------------------------------------

        if ai_probability >= 0.80:

            score += 4

            reasons.append(
                "AI model detected strong phishing characteristics"
            )


        # ---------------------------------------------
        # MEDIUM AI CONFIDENCE
        # ---------------------------------------------

        elif ai_probability >= 0.60:

            score += 3

            reasons.append(
                "AI model detected suspicious characteristics"
            )


        # ---------------------------------------------
        # LOW/MODERATE AI PROBABILITY
        # ---------------------------------------------

        elif ai_probability >= 0.40:

            score += 1

            reasons.append(
                "AI model identified some phishing characteristics"
            )


    # =====================================================
    # HTTP CHECK
    # =====================================================

    if parsed.scheme.lower() == "http":

        score += 2

        reasons.append(
            "Uses HTTP instead of HTTPS"
        )


    # =====================================================
    # URL LENGTH
    # =====================================================

    if len(url) > 75:

        score += 1

        reasons.append(
            "URL is unusually long"
        )


    # =====================================================
    # HYPHEN CHECK
    # =====================================================

    hyphen_count = url.count("-")


    if hyphen_count >= 2:

        score += 2

        reasons.append(
            "Contains multiple hyphens"
        )


    # =====================================================
    # @ SYMBOL
    # =====================================================

    if "@" in url:

        score += 2

        reasons.append(
            "Contains @ symbol"
        )


    # =====================================================
    # IP ADDRESS
    # =====================================================

    hostname = parsed.hostname or ""

    parts = hostname.split(".")


    if (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
    ):

        score += 2

        reasons.append(
            "Uses an IP address instead of a domain name"
        )


    # =====================================================
    # SUSPICIOUS KEYWORDS
    # =====================================================

    suspicious_words = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "bank",
        "paypal",
        "confirm",
        "security"

    ]


    url_lower = url.lower()

    found_words = []


    for word in suspicious_words:

        if word in url_lower:

            found_words.append(word)


    if found_words:

        score += 2

        reasons.append(
            "Contains suspicious keywords"
        )


    # =====================================================
    # GOOGLE SAFE BROWSING
    # =====================================================

    google_threat, threat_types = (
        check_google_safe_browsing(url)
    )


    # =====================================================
    # GOOGLE CONFIRMED THREAT
    # =====================================================

    if google_threat:

        # Google confirmed threat gets maximum score.

        score = 10

        reasons.append(
            "Google Safe Browsing identified this URL "
            "as a known threat"
        )


    # =====================================================
    # LIMIT SCORE
    # =====================================================

    score = min(
        score,
        10
    )


    # =====================================================
    # FINAL PREDICTION
    # =====================================================

    if google_threat:

        prediction = "PHISHING"

        recommendation = (
            "DO NOT visit this website. "
            "Google Safe Browsing has confirmed this URL "
            "as a known security threat."
        )


    elif score >= 5:

        prediction = "PHISHING"

        recommendation = (
            "Avoid visiting this website. "
            "It contains several phishing indicators."
        )


    else:

        prediction = "SAFE"

        recommendation = (
            "This website appears safe based on "
            "our current analysis."
        )


    # =====================================================
    # SAFE WITH NO REASONS
    # =====================================================

    if (
        prediction == "SAFE"
        and not reasons
    ):

        reasons.append(
            "No suspicious indicators detected."
        )


    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score <= 2:

        risk_level = "LOW RISK"

    elif score <= 5:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "HIGH RISK"


    # =====================================================
    # GOOGLE STATUS
    # =====================================================

    if google_threat:

        google_status = "THREAT DETECTED"

    else:

        google_status = "NO KNOWN THREATS"


    # =====================================================
    # GOOGLE THREAT TYPES
    # =====================================================

    google_threat_types = []


    for threat_type in threat_types:

        readable_type = (
            threat_type
            .replace(
                "_",
                " "
            )
            .title()
        )


        google_threat_types.append(
            readable_type
        )


    # =====================================================
    # RETURN RESULTS
    # =====================================================

    return (

        prediction,

        score,

        reasons,

        recommendation,

        google_status,

        google_threat_types,

         ai_probability

    )