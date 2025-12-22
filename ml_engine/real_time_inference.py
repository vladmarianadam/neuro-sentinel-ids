import time
import json
import joblib
import subprocess
import numpy as np
import os
import logging

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

def process_flow_event(event):
    """
    Extracts features from Suricata Flow event and maps to Model Schema.
    """
    try:
        flow = event.get('flow', {})
        
        # FEATURE 1: Flow Duration (Convert Seconds -> Microseconds)
        # Suricata 'age' is in seconds. CICIDS2017 uses microseconds.
        duration_us = flow.get('age', 0) * 1_000_000
        
        # FEATURE 2: Total Fwd Packets (pkts_toserver)
        fwd_pkts = flow.get('pkts_toserver', 0)
        
        # FEATURE 3: Total Bwd Packets (pkts_toclient)
        bwd_pkts = flow.get('pkts_toclient', 0)
        
        # FEATURE 4: Total Fwd Bytes (bytes_toserver)
        fwd_bytes = flow.get('bytes_toserver', 0)
        
        # FEATURE 5: Total Bwd Bytes (bytes_toclient)
        bwd_bytes = flow.get('bytes_toclient', 0)
        
        # Construct Feature Vector
        features = np.array([[duration_us, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes]])
        
        return features
        
    except Exception as e:
        logging.error(f"Feature extraction error: {e}")
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
                    if severity <= 1: 
                        block_ip(src_ip, reason=f"Signature: {signature}")

                # LOGIC B: Anomaly Detection (ML on Flow Completion)
                elif event_type == 'flow':
                    # Only process flows that have actual data transfer
                    if event['flow'].get('bytes_toserver', 0) < 100:
                        continue

                    features = process_flow_event(event)
                    if features is not None:
                        # Scale features
                        features_scaled = scaler.transform(features)
                        # Predict
                        prediction = model.predict(features_scaled)
                        confidence = np.max(model.predict_proba(features_scaled))
                        
                        # 1 = Attack
                        if prediction[0] == 1 and confidence > 0.85:
                            logging.warning(f"[ML] Anomaly Detected! Confidence: {confidence:.2f}")
                            block_ip(src_ip, reason="ML Anomaly Detection")

            except json.JSONDecodeError:
                continue
            except Exception as e:
                logging.error(f"Loop Error: {e}")

if __name__ == "__main__":
    main()