import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Load dataset
data = pd.read_csv("dataset/Phishing_Legitimate_full.csv")

# Features and target
X = data.drop(columns=["id", "CLASS_LABEL"])
y = data["CLASS_LABEL"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Test model
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Create model folder
os.makedirs("model", exist_ok=True)

# Save model
joblib.dump(model, "model/phishing_model.pkl")

print("✅ Model saved successfully!")