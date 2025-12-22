import pandas as pd
import json

def preprocess_eve_log(log_line):
    """
    Parses a single line of eve.json and converts it to the feature vector
    expected by the model.
    """
    try:
        data = json.loads(log_line)
        
        # Example feature extraction (Must match training logic)
        # This is a placeholder. You must map specific eve.json fields 
        # to the columns used in CICIDS2017 training.
        features = {
            "proto": data.get("proto"),
            "src_port": data.get("src_port"),
            "dest_port": data.get("dest_port"),
            # ... add other features
        }
        return features
    except Exception as e:
        return None