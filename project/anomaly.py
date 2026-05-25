# anomaly.py
import numpy as np
from sklearn.ensemble import IsolationForest

X = np.array([[50, 10], [5, 2], [70, 20], [3, 1]])  # example: [event_count, unique_ports]
model = IsolationForest(contamination=0.1, random_state=42).fit(X)
scores = model.decision_function(X)
labels = model.predict(X)  # -1 anomalous, 1 normal


