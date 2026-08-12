import os
import joblib
import pandas as pd

from feature_extractor import extract_features


# =========================================================
# LOAD TRAINED AI MODEL
# =========================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "model",
    "phishing_model.pkl"
)


try:

    saved_data = joblib.load(MODEL_PATH)

    # New model format
    if isinstance(saved_data, dict):

        model = saved_data["model"]

        FEATURE_NAMES = saved_data["features"]

    else:

        # Compatibility with the previous model
        model = saved_data

        FEATURE_NAMES = [
            "url_length",
            "dot_count",
            "hyphen_count",
            "has_at",
            "has_ip",
            "https",
            "no_https",
            "hostname_length",
            "dash_in_hostname",
            "hostname_dots",
            "domain_length",
            "domain_in_subdomains",
            "path_length",
            "domain_in_path",
            "double_slash_in_path",
            "query_length",
            "query_components",
            "ampersand_count",
            "hash_count",
            "percent_count",
            "underscore_count",
            "numeric_chars",
            "sensitive_words",
            "embedded_brand",
            "https_in_hostname"
        ]


    print("AI model loaded successfully.")

    print(
        "AI features:",
        len(FEATURE_NAMES)
    )


except Exception as e:

    model = None

    FEATURE_NAMES = []

    print(
        "ERROR: Could not load AI model:",
        e
    )


# =========================================================
# AI PREDICTION
# =========================================================

def predict_with_ai(url):

    if model is None:

        return None, 0.0


    try:

        # ---------------------------------------------
        # Extract URL features
        # ---------------------------------------------

        features = extract_features(url)


        # ---------------------------------------------
        # Create feature row
        # ---------------------------------------------

        ai_features = {}

        for feature_name in FEATURE_NAMES:

            ai_features[feature_name] = (
                features.get(
                    feature_name,
                    0
                )
            )


        # ---------------------------------------------
        # Create DataFrame
        # ---------------------------------------------

        X = pd.DataFrame(
            [ai_features],
            columns=FEATURE_NAMES
        )


        # ---------------------------------------------
        # AI prediction
        # ---------------------------------------------

        prediction = model.predict(X)[0]


        # ---------------------------------------------
        # AI probability
        # ---------------------------------------------

        if hasattr(
            model,
            "predict_proba"
        ):

            probabilities = model.predict_proba(X)[0]

            classes = list(
                model.classes_
            )


            if 1 in classes:

                phishing_index = (
                    classes.index(1)
                )

                phishing_probability = (
                    probabilities[
                        phishing_index
                    ]
                )

            else:

                phishing_probability = 0.0

        else:

            phishing_probability = (
                1.0
                if prediction == 1
                else 0.0
            )


        return (

            int(prediction),

            float(phishing_probability)

        )


    except Exception as e:

        print(
            "AI prediction error:",
            e
        )

        return None, 0.0