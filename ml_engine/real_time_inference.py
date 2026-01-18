import time
import json
import pandas as pd
import joblib
import subprocess
import numpy as np
import os
import logging
from collections import Counter
import datetime

# Configuration
LOG_FILE = os.getenv('LOG_FILE_PATH', '/var/log/suricata/eve.json')
MODEL_PATH = '/app/models/rf_model.joblib'
SCALER_PATH = '/app/models/scaler.joblib'
BLOCKED_IPS = set()

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load Artifacts
logging.info("Loading ML Model and Scaler...")
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except FileNotFoundError:
    logging.error("Model files not found. Run training first.")
    exit(1)


# Global tracking
dest_hits = Counter()
dest_history = {}

def get_dynamic_count(ip):
    now = datetime.datetime.now()
    if ip not in dest_history:
        dest_history[ip] = []
    
    dest_history[ip].append(now)
    # Clean up old timestamps (2s window)
    dest_history[ip] = [ts for ts in dest_history[ip] if (now - ts).total_seconds() < 2]
    
    return len(dest_history[ip])


def block_ip(ip_address, reason="Anomaly"):
    """
    Executes iptables command to block an IP.
    Requires NET_ADMIN capability and Host Networking.
    """
    if ip_address in BLOCKED_IPS:
        return

    logging.warning(f"Blocking IP: {ip_address} | Reason: {reason}")
    try:
        # 1. Block in DOCKER-USER chain (For traffic destined to containers)
        # This prevents the attack from reaching other containers via the bridge
        subprocess.run(
            ["iptables", "-I", "DOCKER-USER", "-s", ip_address, "-j", "DROP"],
            check=True
        )
        
        # 2. Block in INPUT chain (For traffic destined to the host itself)
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True
        )
        
        BLOCKED_IPS.add(ip_address)
        logging.info(f"Successfully blocked {ip_address}")
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}: {e}")

FEATURE_COLS = [
    'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 
    'serror_rate', 'rerror_rate', 'same_srv_rate', 'diff_srv_rate'
]

def process_flow_event(event):
    try:
        flow = event.get('flow', {})
        # Dynamic: Get the actual destination of this specific packet
        # In a flood, this will be your server's IP
        current_dst = event.get('dest_ip') or event.get('src_ip')
        
        if not current_dst:
            return None

        # Get the count for THIS specific destination
        flood_count = get_dynamic_count(current_dst)

        data = {
            'duration': flow.get('age', 0),
            'src_bytes': flow.get('bytes_toserver', 0),
            'dst_bytes': flow.get('bytes_toclient', 0),
            'count': flood_count,
            'srv_count': flood_count, 
            'serror_rate': 1.0 if flow.get('bytes_toclient', 0) == 0 else 0.0,
            'rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0
        }

        return pd.DataFrame([data], columns=FEATURE_COLS)
    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def main():
    logging.info(f"Tailing log file: {LOG_FILE}")
    
    # Open file and move pointer to the end (tail -f behavior)
    # We don't want to process historical logs on startup
    with open(LOG_FILE, 'r') as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                event = json.loads(line)
                event_type = event.get('event_type')
                src_ip = event.get('src_ip')
                
                if not src_ip:
                    continue

                # IGNORE local traffic (Don't block the dashboard or yourself)
                if src_ip in ['127.0.0.1', '::1', 'localhost'] or src_ip.startswith('192.168.1.'):
                    continue

                # LOGIC A: Signature Detection (Suricata Alert)
                if event_type == 'alert':
                    signature = event['alert']['signature']
                    severity = event['alert'].get('severity', 3)
                    logging.info(f" Alert: {signature} from {src_ip}")
                    
                    # Immediate blocking for high severity signature matches
                    if severity <= 3: 
                        block_ip(src_ip, reason=f"Signature: {signature}")

                # LOGIC B: Anomaly Detection (ML on Flow Completion)
                elif event_type == 'flow':
                    # print(event)
                    # Only process flows that have actual data transfer
                    if event['flow'].get('bytes_toserver', 0) < 10:
                        continue

                    features_df = process_flow_event(event)
                    if features_df is not None:
                        features_scaled = scaler.transform(features_df)
                        # Predict
                        # print(f"DEBUG FEATURES: {features_df.values}")
                        prediction = model.predict(features_scaled)
                        # print("prediction:", prediction)
                        confidence = np.max(model.predict_proba(features_scaled))
                        # print("confidence:", confidence)
                        
                        # 1 = Attack
                        if prediction[0] == 1:
                            # Dacă zice clar că e atac, blocăm
                            logging.warning(f"[ML] Atac Detectat! Confidence: {confidence:.2f}")
                            block_ip(src_ip, reason="ML Attack Prediction")

                        elif prediction[0] == 0 and confidence < 0.85:
                            # Dacă zice că e Normal, dar e nesigur (sub 85%), e suspect
                            logging.warning(f"[ML] Trafic Suspect! (Normal dar nesigur: {confidence:.2f})")
                            
                            # Verificăm dacă e tiparul de SYN Flood (multe pachete fără răspuns)
                            if features_df['serror_rate'].iloc[0] == 1.0:
                                logging.warning(f"-> Tipar SYN Flood detectat (Serror=1). Blocăm!")
                                block_ip(src_ip, reason="Low Confidence + Serror Rate")

            except json.JSONDecodeError:
                continue
            except Exception as e:
                logging.error(f"Loop Error: {e}")

if __name__ == "__main__":
    main()
