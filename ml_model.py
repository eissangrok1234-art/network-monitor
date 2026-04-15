import numpy as np
from sklearn.ensemble import IsolationForest

# نموذج عالمي
model = IsolationForest(contamination=0.2)

# Simple training data(Natural)
# [Number of devices, Number of ports]
training_data = np.array([
    [5, 2],
    [6, 3],
    [4, 1],
    [7, 2],
    [5, 3],
    [6, 2]
])

#  training the model
model.fit(training_data)

# =========================
# 🧠  network analysis
# =========================
def detect_anomaly(devices, ports_data):
    total_ports = sum(len(p) for p in ports_data.values())

    test_data = np.array([[len(devices), total_ports]])

    prediction = model.predict(test_data)

    # -1 = anomaly
    if prediction[0] == -1:
        return "⚠️ AI detected abnormal network behavior!"
    else:
        return "✅ Network behavior is normal"