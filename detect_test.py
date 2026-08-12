from detector import detect_phishing

url = input("Enter URL: ")

prediction, score, reasons = detect_phishing(url)

print("\n========== RESULT ==========\n")

print("Prediction :", prediction)
print("Risk Score :", score)

print("\nReasons:")

if reasons:
    for reason in reasons:
        print("-", reason)
else:
    print("No suspicious indicators found.")