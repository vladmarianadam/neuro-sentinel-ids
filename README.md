# Hybrid IDS Project

A containerized Intrusion Detection System combining Suricata (Signature-based) and Machine Learning (Anomaly-based).

## Structure

*   **infrastructure/**: Suricata IDS configuration and rules.
*   **ml_engine/**: Python service for real-time anomaly detection.
*   **dashboard/**: Streamlit visualization of alerts.
*   **logs/**: Shared volume for `eve.json`.

## Usage

1.  Place your trained models in `ml_engine/models/`.
2.  Configure `.env` with your network interface.
3.  Run:
    ```bash
    docker-compose up --build -d
    ```

## Requirements

*   Docker & Docker Compose
*   Python 3.9+ (for offline training)