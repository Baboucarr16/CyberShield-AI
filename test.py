from feature_extractor import extract_features

url = input("Enter a URL: ")

features = extract_features(url)

print("\n========== FEATURES ==========\n")

for key, value in features.items():
    print(f"{key:20} : {value}")