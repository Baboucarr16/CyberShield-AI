import os
import sys
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Project root
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)

from feature_extractor import extract_features


# =========================================================
# PATHS
# =========================================================

DATASET_PATH = os.path.join(
    PROJECT_ROOT,
    "Phishing_Legitimate_full.csv"
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "model",
    "phishing_model.pkl"
)


# =========================================================
# FEATURES
# These names MUST match feature_extractor.py
# =========================================================

FEATURE_NAMES = [

    "url_length",

    "dot_count",

    "hyphen_count",

    "has_at",

    "has_ip",

    "sensitive_words",

    "hostname_length",

    "path_length",

    "query_length",

    "double_slash_in_path",

    "domain_in_subdomains",

    "numeric_chars",

    "no_https"

]


# =========================================================
# LOAD DATASET
# =========================================================

print("=" * 60)
print("CYBERSHIELD AI - MODEL TRAINING")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully.")

print(
    "Total records:",
    len(df)
)


# =========================================================
# REQUIRED DATASET COLUMNS
# =========================================================

DATASET_COLUMNS = [

    "UrlLength",
    "NumDots",
    "NumDash",
    "AtSymbol",
    "IpAddress",
    "NumSensitiveWords",
    "HostnameLength",
    "PathLength",
    "QueryLength",
    "DoubleSlashInPath",
    "DomainInSubdomains",
    "NumNumericChars",
    "NoHttps",
    "CLASS_LABEL"

]


# =========================================================
# CHECK COLUMNS
# =========================================================

missing = [

    column
    for column in DATASET_COLUMNS
    if column not in df.columns

]


if missing:

    print("\nERROR!")

    print("Missing columns:")

    for column in missing:
        print("-", column)

    print("\nTraining stopped.")

    sys.exit(1)


# =========================================================
# CREATE FEATURES
# =========================================================

print("\nPreparing features...")


X = pd.DataFrame({

    "url_length":
        df["UrlLength"],

    "dot_count":
        df["NumDots"],

    "hyphen_count":
        df["NumDash"],

    "has_at":
        df["AtSymbol"],

    "has_ip":
        df["IpAddress"],

    "sensitive_words":
        df["NumSensitiveWords"],

    "hostname_length":
        df["HostnameLength"],

    "path_length":
        df["PathLength"],

    "query_length":
        df["QueryLength"],

    "double_slash_in_path":
        df["DoubleSlashInPath"],

    "domain_in_subdomains":
        df["DomainInSubdomains"],

    "numeric_chars":
        df["NumNumericChars"],

    "no_https":
        df["NoHttps"]

})


# =========================================================
# TARGET
# =========================================================

y = df["CLASS_LABEL"]


print(
    "Features:",
    X.shape
)

print(
    "\nClass distribution:"
)

print(
    y.value_counts()
)


# =========================================================
# TRAIN / TEST SPLIT
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(

    X,

    y,

    test_size=0.20,

    random_state=42,

    stratify=y

)


print(
    "\nTraining records:",
    len(X_train)
)

print(
    "Testing records:",
    len(X_test)
)


# =========================================================
# RANDOM FOREST
# =========================================================

print(
    "\nCreating Random Forest..."
)


model = RandomForestClassifier(

    n_estimators=300,

    random_state=42,

    class_weight="balanced",

    n_jobs=-1

)


# =========================================================
# TRAIN
# =========================================================

print(
    "Training AI model..."
)


model.fit(

    X_train,

    y_train

)


print(
    "Training completed!"
)


# =========================================================
# TEST
# =========================================================

predictions = model.predict(

    X_test

)


# =========================================================
# ACCURACY
# =========================================================

accuracy = accuracy_score(

    y_test,

    predictions

)


print(
    "\n" + "=" * 60
)

print(
    "AI MODEL RESULTS"
)

print(
    "=" * 60
)

print(
    "Accuracy:",
    round(
        accuracy * 100,
        2
    ),
    "%"
)


# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print(
    "\nClassification Report:"
)

print(
    classification_report(

        y_test,

        predictions

    )
)


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

print(
    "\nFeature Importance:"
)


importance = pd.Series(

    model.feature_importances_,

    index=FEATURE_NAMES

).sort_values(

    ascending=False

)


for feature, value in importance.items():

    print(
        f"{feature}: {value:.4f}"
    )


# =========================================================
# SAVE MODEL
# =========================================================

os.makedirs(

    os.path.dirname(
        MODEL_PATH
    ),

    exist_ok=True

)


joblib.dump(

    {
        "model": model,
        "features": FEATURE_NAMES
    },

    MODEL_PATH

)


# =========================================================
# DONE
# =========================================================

print(
    "\n" + "=" * 60
)

print(
    "MODEL SAVED SUCCESSFULLY"
)

print(
    "=" * 60
)

print(
    MODEL_PATH
)

print(
    "\nCyberShield AI training complete!"
)