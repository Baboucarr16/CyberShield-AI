"""Small command-line smoke test for the detector."""
from detector import detect_phishing


if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    try:
        prediction, score, reasons, recommendation = detect_phishing(url)
    except ValueError as exc:
        raise SystemExit(str(exc))
    print("\n========== RESULT ==========\n")
    print("Prediction:", prediction)
    print("Risk score:", score, "/ 10")
    print("\nReasons:")
    for reason in reasons:
        print("-", reason)
    print("\nRecommendation:", recommendation)
