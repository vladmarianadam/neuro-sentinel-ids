import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os

# Creează folderele dacă nu există
os.makedirs('models', exist_ok=True)

# Generăm date false (5 coloane: duration, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes)
X = np.random.rand(100, 5) 
y = np.random.randint(0, 2, 100) # 0 = Normal, 1 = Atac

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = RandomForestClassifier(n_estimators=10)
model.fit(X_scaled, y)

joblib.dump(model, 'models/rf_model.joblib')
joblib.dump(scaler, 'models/scaler.joblib')

print("Succes! Modelele dummy au fost create în ml_engine/models/")