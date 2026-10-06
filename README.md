# CyberShield AI

CyberShield AI is a Flask application that screens URL structure using a Random Forest and a rule-based detector. It does not fetch submitted pages; results are advisory and cannot guarantee a site is safe.

## Detection and model limits

Training uses `dataset/Phishing_Legitimate_full.csv` (10,000 rows, 48 numeric features, labels 0/1). The latest deterministic 80/20 stratified holdout run achieved **98.45% accuracy on that dataset**. This is not a real-world URL accuracy claim.

The shared `model_features.py` schema fixes the exact 48 feature names and order for both training and inference. Live inference can derive 21 structural values from the URL. The remaining 27 CSV features depend on page content, links, forms, or browser behavior and are set to zero because this application does not retrieve webpage content. The Random Forest's class-1 probability is shown separately from the final 0-10 risk score. For scoring, model probability contributes `floor(probability * 8)` points (so 50% contributes 4 points); rule indicators contribute up to 10 points. The final score is the greater of those two signals, capped at 10. Scores of 4 or more are classified as phishing. If a valid model artifact is absent or incompatible, URL rule detection remains available and the model probability is unavailable.

Google Safe Browsing is **not implemented**. The scanner makes no Safe Browsing request and does not need an API key. There is currently no PDF report generator or download route. Scan history is stored in browser local storage, not by the backend.

## Local setup

Use Python 3.10 or newer. From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python model/train_model.py
python app.py
```

Open `http://127.0.0.1:5000/scanner`. Training reads the dataset and writes `model/phishing_model.joblib` relative to the project files. The generated artifact is ignored by Git.

## Render deployment

Configure the Render web service with:

- **Build command:** `pip install -r requirements.txt && python model/train_model.py`
- **Start command:** `gunicorn app:app`
- **Environment:** set a long, random `SECRET_KEY`; leave `FLASK_DEBUG` unset or set it to `0`.

Training during build creates the ignored model artifact on the deployed build image. Confirm the dataset is included in the deployment source. The application generates a secure per-process fallback secret if `SECRET_KEY` is missing, but production should set a stable secret explicitly.

## Tests and CLI

```powershell
python -m pytest -q
python detect_test.py
```
