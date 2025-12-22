import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
import joblib

def train_ids_model():
    print("Loading CICIDS2017 Dataset...")
    # Load a subset of the dataset (e.g., Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv)
    # In production, you would concatenate all days.
    df = pd.read_csv("datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    # Clean Column Names (Strip whitespace)
    df.columns = df.columns.str.strip()

    # 1. Feature Selection
    # We must ONLY select features that we can extract from Suricata's 'flow' log.
    # Suricata provides: Duration, Pkts/Bytes (Source/Dest).
    # We map CICIDS2017 columns to Suricata equivalent logic.
    selected_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets']
    
    X = df[selected_features]
    y = df['Label']

    # 2. Data Cleaning
    # CICIDS2017 contains Infinity and NaN values
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna()
    y = y[X.index] # Align target with dropped rows

    # 3. Encoding Target
    # Convert 'BENIGN' to 0 and Attacks to 1 (Binary Classification)
    y = y.apply(lambda x: 0 if x == 'BENIGN' else 1)

    # 4. Splitting
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Scaling
    # Essential for models like SVM, good practice for Forest
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 6. Model Training (Random Forest)
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    # 7. Evaluation
    print("Evaluating...")
    y_pred = rf.predict(X_test_scaled)
    print(classification_report(y_test, y_pred))

    # 8. Serialization
    # Save the model and the scaler for the inference engine
    print("Saving artifacts...")
    joblib.dump(rf, 'models/rf_model.joblib')
    joblib.dump(scaler, 'models/scaler.joblib')
    print("Done.")

if __name__ == "__main__":
    train_ids_model()