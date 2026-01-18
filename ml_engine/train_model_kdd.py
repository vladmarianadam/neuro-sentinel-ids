"""
KDD NSL Dataset Training Script for Neuro-Sentinel IDS
=======================================================

Trains ML models using the KDD NSL dataset for intrusion detection.
Features are selected to match what Suricata eve.json can provide.

Usage:
    python train_model_kdd.py [--model rf|xgb|svm] [--multiclass]

Dataset: KDDTrain+.txt (NSL-KDD dataset)
"""

import argparse
import os
import sys
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# KDD NSL Column Names (41 features + label + difficulty)
KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# Features that can be extracted from Suricata eve.json flow events
# These map to KDD features as follows:
#   - duration -> flow.age (seconds)
#   - protocol_type -> proto (tcp/udp/icmp)
#   - src_bytes -> flow.bytes_toserver
#   - dst_bytes -> flow.bytes_toclient
#   - count -> approximated from flow rate
SURICATA_COMPATIBLE_FEATURES = [
    'duration',       # flow.age in Suricata
    'src_bytes',      # flow.bytes_toserver
    'dst_bytes',      # flow.bytes_toclient
    'count',          # connection count (can be tracked)
    'srv_count',      # service connection count
    'serror_rate',    # SYN error rate
    'rerror_rate',    # REJ error rate
    'same_srv_rate',  # same service rate
    'diff_srv_rate',  # different service rate
]

# Attack category mapping
ATTACK_CATEGORIES = {
    'normal': 'normal',
    # DoS attacks
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
    'smurf': 'dos', 'teardrop': 'dos', 'apache2': 'dos', 'udpstorm': 'dos',
    'processtable': 'dos', 'mailbomb': 'dos',
    # Probe attacks
    'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',
    # R2L attacks
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l',
    'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l', 'snmpguess': 'r2l',
    'xlock': 'r2l', 'xsnoop': 'r2l',
    # U2R attacks
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
    'sqlattack': 'u2r', 'xterm': 'u2r', 'ps': 'u2r'
}


def get_script_dir():
    """Get the directory where this script is located."""
    return os.path.dirname(os.path.abspath(__file__))


def load_kdd_dataset(dataset_path):
    """Load and parse the KDD NSL dataset."""
    print(f"Loading dataset from: {dataset_path}")

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path, names=KDD_COLUMNS, header=None)
    print(f"Loaded {len(df):,} records with {len(df.columns)} columns")

    return df


def preprocess_data(df, multiclass=False):
    """
    Preprocess the KDD dataset for training.

    Args:
        df: Raw DataFrame
        multiclass: If True, use attack categories (5 classes).
                   If False, use binary (normal vs attack).
    """
    print("\nPreprocessing data...")

    # Select Suricata-compatible features
    X = df[SURICATA_COMPATIBLE_FEATURES].copy()

    # Handle labels
    if multiclass:
        # Map to 5 categories: normal, dos, probe, r2l, u2r
        df['category'] = df['label'].map(ATTACK_CATEGORIES)
        y = df['category']
        print(f"Using multiclass classification (5 categories)")
    else:
        # Binary: 0 = normal, 1 = attack
        y = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
        print(f"Using binary classification (normal vs attack)")

    # Handle missing/infinite values
    X = X.replace([np.inf, -np.inf], np.nan)
    initial_count = len(X)

    # Fill NaN with median (more robust than mean for skewed data)
    X = X.fillna(X.median())

    print(f"Features selected: {list(X.columns)}")
    print(f"Records after cleaning: {len(X):,}")

    # Show class distribution
    print("\nClass distribution:")
    class_counts = y.value_counts()
    for label, count in class_counts.items():
        print(f"  {label}: {count:,} ({count/len(y)*100:.1f}%)")

    return X, y


def encode_labels(y, multiclass=False):
    """Encode labels for model training."""
    if multiclass:
        encoder = LabelEncoder()
        y_encoded = encoder.fit_transform(y)
        return y_encoded, encoder
    else:
        return y.values, None


def train_model(X_train, y_train, model_type='rf'):
    """
    Train the specified model type.

    Args:
        X_train: Training features
        y_train: Training labels
        model_type: 'rf' (Random Forest), 'xgb' (Gradient Boosting), 'svm' (SVM)
    """
    print(f"\nTraining {model_type.upper()} model...")

    if model_type == 'rf':
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
    elif model_type == 'xgb':
        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=10,
            learning_rate=0.1,
            random_state=42
        )
    elif model_type == 'svm':
        model = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,
            random_state=42,
            class_weight='balanced'
        )
    else:
        raise ValueError(f"Unknown model type: {model_type}")

    model.fit(X_train, y_train)
    print("Training complete!")

    return model


def evaluate_model(model, X_test, y_test, label_encoder=None):
    """Evaluate model performance."""
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)

    y_pred = model.predict(X_test)

    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

    # Classification report
    if label_encoder:
        target_names = label_encoder.classes_
    else:
        target_names = ['Normal', 'Attack']

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Confusion matrix
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    return accuracy, y_pred


def save_artifacts(model, scaler, label_encoder, feature_names, model_type, output_dir):
    """Save trained model and preprocessing artifacts."""
    os.makedirs(output_dir, exist_ok=True)

    # Save model
    model_path = os.path.join(output_dir, 'rf_model.joblib')
    joblib.dump(model, model_path)
    print(f"\nModel saved to: {model_path}")

    # Save scaler
    scaler_path = os.path.join(output_dir, 'scaler.joblib')
    joblib.dump(scaler, scaler_path)
    print(f"Scaler saved to: {scaler_path}")

    # Save label encoder if multiclass
    if label_encoder:
        encoder_path = os.path.join(output_dir, 'label_encoder.joblib')
        joblib.dump(label_encoder, encoder_path)
        print(f"Label encoder saved to: {encoder_path}")

    # Save metadata
    metadata = {
        'model_type': model_type,
        'feature_names': feature_names,
        'training_date': datetime.now().isoformat(),
        'dataset': 'KDD NSL (KDDTrain+.txt)',
        'multiclass': label_encoder is not None,
        'classes': list(label_encoder.classes_) if label_encoder else ['normal', 'attack']
    }

    metadata_path = os.path.join(output_dir, 'model_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")


def print_feature_importance(model, feature_names, model_type):
    """Print feature importance if available."""
    if hasattr(model, 'feature_importances_'):
        print("\n" + "="*60)
        print("FEATURE IMPORTANCE")
        print("="*60)

        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]

        for i, idx in enumerate(indices):
            print(f"  {i+1}. {feature_names[idx]}: {importances[idx]:.4f}")


def main():
    parser = argparse.ArgumentParser(
        description='Train IDS model using KDD NSL dataset'
    )
    parser.add_argument(
        '--model', '-m',
        choices=['rf', 'xgb', 'svm'],
        default='rf',
        help='Model type: rf (Random Forest), xgb (Gradient Boosting), svm (SVM)'
    )
    parser.add_argument(
        '--multiclass', '-c',
        action='store_true',
        help='Use multiclass classification (5 categories) instead of binary'
    )
    parser.add_argument(
        '--dataset', '-d',
        default=None,
        help='Path to KDDTrain+.txt dataset'
    )
    parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output directory for model artifacts'
    )
    parser.add_argument(
        '--test-size', '-t',
        type=float,
        default=0.2,
        help='Test set size (default: 0.2)'
    )

    args = parser.parse_args()

    # Resolve paths
    script_dir = get_script_dir()

    if args.dataset:
        dataset_path = args.dataset
    else:
        dataset_path = os.path.join(script_dir, 'dataset', 'KDDTrain+.txt')

    if args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(script_dir, 'models')

    print("="*60)
    print("NEURO-SENTINEL IDS - MODEL TRAINING")
    print("="*60)
    print(f"Model type: {args.model.upper()}")
    print(f"Classification: {'Multiclass (5 categories)' if args.multiclass else 'Binary (normal/attack)'}")
    print(f"Test size: {args.test_size}")

    try:
        # Load data
        df = load_kdd_dataset(dataset_path)

        # Preprocess
        X, y = preprocess_data(df, multiclass=args.multiclass)

        # Encode labels
        y_encoded, label_encoder = encode_labels(y, multiclass=args.multiclass)

        # Split data
        print(f"\nSplitting data ({int((1-args.test_size)*100)}% train, {int(args.test_size*100)}% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded,
            test_size=args.test_size,
            random_state=42,
            stratify=y_encoded
        )
        print(f"Training set: {len(X_train):,} samples")
        print(f"Test set: {len(X_test):,} samples")

        # Scale features
        print("\nScaling features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train model
        model = train_model(X_train_scaled, y_train, model_type=args.model)

        # Evaluate
        accuracy, y_pred = evaluate_model(model, X_test_scaled, y_test, label_encoder)

        # Feature importance
        print_feature_importance(model, list(X.columns), args.model)

        # Save artifacts
        save_artifacts(
            model, scaler, label_encoder,
            list(X.columns), args.model, output_dir
        )

        print("\n" + "="*60)
        print("TRAINING COMPLETE!")
        print("="*60)
        print(f"Final accuracy: {accuracy*100:.2f}%")
        print(f"Model saved to: {output_dir}")

    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        print("Make sure the KDDTrain+.txt dataset is in the dataset folder.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
