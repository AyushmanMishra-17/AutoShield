import numpy as np
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

FEATURES = ("requests", "failedLogins", "requestRate", "timeGap")

X_train = np.array(
    [
        [10, 1, 2, 5],
        [20, 0, 3, 4],
        [15, 1, 2, 6],
        [18, 2, 3, 5],
        [25, 1, 4, 3],
        [60, 8, 7, 1.2],
        [380, 1, 18, 0.2],
        [110, 25, 9, 0.4],
    ],
    dtype=float,
)

model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X_train)


def read_features(payload):
    if not isinstance(payload, dict):
        raise ValueError("JSON object expected")

    values = []
    for field in FEATURES:
        if field not in payload:
            raise ValueError(f"Missing field: {field}")
        try:
            values.append(float(payload[field]))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Field must be numeric: {field}") from exc

    if any(value < 0 for value in values):
        raise ValueError("Feature values must be non-negative")

    return np.array([values], dtype=float)


def explain(values, score, is_anomaly):
    requests, failed_logins, request_rate, time_gap = values

    if not is_anomaly:
        return "Traffic remains close to the learned baseline."
    if requests > 250 or request_rate > 15:
        return "High request volume and request rate match a DDoS-like pattern."
    if failed_logins > 10:
        return "Repeated failed logins match a brute-force pattern."
    if time_gap < 0.5:
        return "Very small request gaps indicate automated traffic."

    return f"Combined feature drift crossed the anomaly boundary ({score:.3f})."


@app.get("/health")
def health():
    return jsonify({"ok": True, "model": "IsolationForest", "features": FEATURES})


@app.route("/predict", methods=["POST"])
def predict():
    try:
        features = read_features(request.get_json(silent=True))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    score = float(model.decision_function(features)[0])
    prediction = int(model.predict(features)[0])
    is_anomaly = prediction == -1
    confidence = min(1.0, abs(score) * 2.5)

    return jsonify({
        "anomaly_score": score,
        "confidence": confidence,
        "is_anomaly": is_anomaly,
        "explanation": explain(features[0], score, is_anomaly),
    })


if __name__ == "__main__":
    app.run(port=8000)
