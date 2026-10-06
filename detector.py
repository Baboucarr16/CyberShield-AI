from feature_extractor import extract_features
from ai_model import predict_url


def analyze_url(url):
    features = extract_features(url)
    reasons = []
    rule_score = 0
    checks = [
        (features["https"] == 0, 2, "Uses HTTP instead of HTTPS"),
        (features["url_length"] > 75, 1, "URL is unusually long"),
        (features["hyphen_count"] >= 2, 1, "Contains multiple hyphens"),
        (features["has_at"] == 1, 2, "Contains '@' symbol"),
        (features["has_ip"] == 1, 2, "Contains an IP address"),
        (features["suspicious_words"] >= 1, min(2, features["suspicious_words"]), "Contains suspicious keywords"),
        (features["dot_count"] > 4, 1, "Too many dots in the URL"),
    ]
    for matched, points, reason in checks:
        if matched:
            rule_score += points
            reasons.append(reason)

    rule_score = min(10, rule_score)
    try:
        probability = predict_url(features)
    except Exception as exc:
        # A malformed or incompatible artifact must not prevent rules-only scans.
        import logging
        logging.getLogger(__name__).warning(
            "Random Forest inference failed (%s); using rule-based detection",
            type(exc).__name__,
        )
        probability = None
    # The model contributes up to 8 points; p=0.5 maps to the shared 4-point
    # verdict boundary. Rules can contribute up to 10 points independently.
    model_score = int(probability * 8) if probability is not None else 0
    score = min(10, max(rule_score, model_score))
    prediction = "PHISHING" if score >= 4 else "LEGITIMATE"
    if prediction == "PHISHING":
        recommendation = "Avoid visiting this website. It contains phishing indicators."
    else:
        recommendation = "No strong phishing indicators were found. This check cannot guarantee a website is safe."
    if not reasons:
        reasons.append("No suspicious indicators detected.")
    return {
        "normalized_url": features["full_url"],
        "prediction": prediction,
        "score": score,
        "reasons": reasons,
        "recommendation": recommendation,
        "model_probability": probability,
    }


def detect_phishing(url):
    """Keep the established four-value CLI/API contract."""
    result = analyze_url(url)
    return (result["prediction"], result["score"], result["reasons"], result["recommendation"])
