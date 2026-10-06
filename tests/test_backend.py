import csv
import importlib
from pathlib import Path

import pytest
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

import ai_model
import config
import detector
from app import create_app
from feature_extractor import extract_features, normalize_url
from model_features import FEATURE_COLUMNS, to_model_row

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rules_only(monkeypatch):
    monkeypatch.setattr(detector, "predict_url", lambda _features: None)


def test_normalizes_and_extracts_https_and_http():
    https = extract_features("https://example.com/path?q=1")
    http = extract_features("http://example.com/path?q=1")
    assert https["https"] == 1
    assert http["https"] == 0
    assert https["hostname"] == "example.com"
    assert https["path"] == "/path"
    assert https["query"] == "q=1"
    assert normalize_url("example.com") == "https://example.com/"


@pytest.mark.parametrize("url", ["", "   ", "javascript:alert(1)", "https:///missing-host", "https://999.999.1.2", "https://user:secret@example.com", "https://example.com\\@evil.test", "https://bad host.test"])
def test_rejects_malformed_or_unsafe_urls(url):
    with pytest.raises(ValueError):
        extract_features(url)


@pytest.mark.parametrize(("url", "expected"), [
    ("https://192.0.2.10/login", 1),
    ("http://[2001:db8::1]/", 1),
    ("https://example.com/", 0),
])
def test_ip_feature(url, expected):
    assert extract_features(url)["has_ip"] == expected


def test_feature_schema_matches_dataset_header():
    with open(PROJECT_ROOT / "dataset" / "Phishing_Legitimate_full.csv", newline="", encoding="utf-8") as dataset:
        header = next(csv.reader(dataset))
    assert tuple(name for name in header if name not in ("id", "CLASS_LABEL")) == FEATURE_COLUMNS
    row = to_model_row(extract_features("https://www.example.com/login"))
    assert tuple(row) == FEATURE_COLUMNS
    assert row["NoHttps"] == 0
    assert row["NumSensitiveWords"] == 1
    assert row["PctExtHyperlinks"] == 0  # page content is unavailable to URL-only scans
    ip_row = to_model_row(extract_features("https://192.0.2.1/"))
    assert ip_row["SubdomainLevel"] == 0


def test_model_prediction_is_a_phishing_probability(monkeypatch, tmp_path):
    train_x = pd.DataFrame(
        [[0] * len(FEATURE_COLUMNS), [1] * len(FEATURE_COLUMNS)],
        columns=FEATURE_COLUMNS,
    )
    model = RandomForestClassifier(n_estimators=3, random_state=1).fit(train_x, [0, 1])
    model_path = tmp_path / "model.joblib"
    joblib.dump({"version": 1, "model": model, "feature_columns": list(FEATURE_COLUMNS)}, model_path)
    monkeypatch.setattr(ai_model, "MODEL_PATH", model_path)
    ai_model._load_model.cache_clear()
    features = extract_features("https://example.com/login")
    probability = ai_model.predict_url(features)
    assert 0.0 <= probability <= 1.0
    assert ai_model._load_model().n_features_in_ == len(FEATURE_COLUMNS)
    ai_model._load_model.cache_clear()


def test_missing_or_corrupt_model_degrades_to_rules(monkeypatch, tmp_path, caplog):
    model_path = tmp_path / "bad-model.joblib"
    monkeypatch.setattr(ai_model, "MODEL_PATH", model_path)
    ai_model._load_model.cache_clear()
    assert ai_model.predict_url(extract_features("https://example.com")) is None
    model_path.write_text("not a model", encoding="utf-8")
    ai_model._load_model.cache_clear()
    assert ai_model.predict_url(extract_features("https://example.com")) is None
    assert "using rule-based detection" in caplog.text
    ai_model._load_model.cache_clear()


def test_detector_rules_and_model_risk_boundaries(monkeypatch, rules_only):
    safe = detector.detect_phishing("https://example.com")
    http = detector.detect_phishing("http://example.com")
    ip = detector.detect_phishing("https://192.0.2.10")
    keyword = detector.detect_phishing("https://example.com/login")
    phishing_like = detector.detect_phishing("http://secure-login.example.com")
    assert safe[0] == "LEGITIMATE" and safe[1] == 0
    assert http[1] == 2 and http[0] == "LEGITIMATE"
    assert ip[1] == 2 and ip[0] == "LEGITIMATE"
    assert "suspicious keywords" in " ".join(keyword[2])
    assert phishing_like[0] == "PHISHING" and phishing_like[1] >= 4

    monkeypatch.setattr(detector, "predict_url", lambda _features: 0.499)
    assert detector.detect_phishing("https://example.com")[1:2] == (3,)
    assert detector.detect_phishing("https://example.com")[0] == "LEGITIMATE"
    monkeypatch.setattr(detector, "predict_url", lambda _features: 0.5)
    verdict, score, _, _ = detector.detect_phishing("https://example.com")
    assert verdict == "PHISHING" and score == 4
    monkeypatch.setattr(detector, "predict_url", lambda _features: 1.0)
    assert detector.detect_phishing("https://example.com")[1] == 8


def test_score_never_exceeds_display_range(monkeypatch):
    monkeypatch.setattr(detector, "predict_url", lambda _features: None)
    verdict, score, _, _ = detector.detect_phishing(
        "http://192.0.2.1/a-b-c-login-verify.foo.bar.baz.qux/@/" + "a" * 100
    )
    assert score == 10
    assert verdict == "PHISHING"


def test_scanner_route_and_invalid_input(rules_only):
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    assert client.get("/scanner").status_code == 200
    result = client.post("/scanner", data={"url": "https://example.com"})
    assert result.status_code == 200
    assert b"data-result" in result.data
    assert b"Unavailable" in result.data
    invalid = client.post("/scanner", data={"url": "javascript:alert(1)"})
    assert invalid.status_code == 200
    assert b"data-result" not in invalid.data


def test_all_frontend_get_routes(rules_only):
    client = create_app().test_client()
    for route in ("/", "/scanner", "/dashboard", "/case-study", "/about"):
        assert client.get(route).status_code == 200


def test_model_inference_error_does_not_break_scanner(monkeypatch):
    def broken_model(_features):
        raise RuntimeError("private model path should not reach users")

    monkeypatch.setattr(detector, "predict_url", broken_model)
    response = create_app().test_client().post("/scanner", data={"url": "http://example.com"})
    assert response.status_code == 200
    assert b"data-result" in response.data
    assert b"private model path" not in response.data
    assert b"Unavailable" in response.data


def test_flask_escapes_submitted_url(rules_only):
    client = create_app().test_client()
    response = client.post("/scanner", data={"url": "https://example.com/<script>"})
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data


def test_secret_key_fallback_and_debug_default(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    reloaded = importlib.reload(config)
    first_secret = reloaded.Config.SECRET_KEY
    assert reloaded.Config.DEBUG is False
    assert len(first_secret) >= 32
    reloaded = importlib.reload(config)
    assert reloaded.Config.SECRET_KEY != first_secret
