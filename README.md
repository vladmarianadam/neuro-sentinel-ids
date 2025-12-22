# 🛡️ NeuroSentinel: Hybrid ML-Powered IDS/IPS

![Docker](https://img.shields.io/badge/Docker-Enabled-blue?logo=docker)
![Python](https://img.shields.io/badge/Python-3.9+-yellow?logo=python)
![Snort](https://img.shields.io/badge/Engine-Snort%2FSuricata-red)
![ML](https://img.shields.io/badge/Model-RandomForest%2FSVM-green)

**NeuroSentinel** is a containerized, hybrid Intrusion Detection and Prevention System (IDS/IPS). It combines traditional signature-based detection (Snort/Suricata) with anomaly-based Machine Learning models to detect both known threats and zero-day attacks in real-time.

---

## 🏗️ System Architecture

The project utilizes **Docker Compose** to orchestrate four isolated services:

1.  **🔍 IDS/IPS Engine (The Watchman):**
    * Runs **Snort** or **Suricata** in inline/passive mode.
    * Captures traffic and matches against signature rules (DoS, signatures).
    * Writes logs (`eve.json` / `alert`) to a shared Docker volume.
2.  **🧠 ML Engine (The Brain):**
    * Python-based service monitoring the shared logs in real-time.
    * Preprocesses data and runs inference using a trained model (**Random Forest** or **SVM**).
    * Trained on **NSL-KDD** or **CICIDS2017** datasets.
    * Triggers automated blocking actions upon anomaly detection.
3.  **📊 Dashboard (The View):**
    * Visual interface (Streamlit or ELK Stack) for reporting security alerts and performance metrics.
4.  **⚔️ Attack Simulator (The Test - *Optional*):**
    * Isolated container running `hping3` or `Hydra` to safely simulate attacks within the Docker network.

---

## 👥 Team Roles & Responsibilities

This project is divided into two distinct engineering tracks:

### 🔧 Role A: Infrastructure & Network (The Backbone)
* **Focus:** Network Layer, Docker Networking, Rule-Based Logic.
* **Responsibilities:**
    * Setting up the `docker-compose` environment and networks.
    * Configuring Snort/Suricata rules (Signature detection).
    * Managing `iptables` and Linux capabilities (`NET_ADMIN`).
    * Ensuring logs are correctly piped to shared volumes.

### 🧪 Role B: Data Science & Intelligence (The Mind)
* **Focus:** ML Pipeline, Data Preprocessing, Inference Scripting.
* **Responsibilities:**
    * Cleaning and normalizing datasets (NSL-KDD/CICIDS2017).
    * Training and exporting the ML model (`.pkl` / `.joblib`).
    * Writing the Python script to parse `eve.json` and predict anomalies.
    * Developing the visualization dashboard.

---

## 🚀 Getting Started

### Prerequisites
* Docker & Docker Compose installed.
* Python 3.9+ (for local model training).
* Basic understanding of TCP/IP and Networking.

### Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/neuro-sentinel-ids.git](https://github.com/yourusername/neuro-sentinel-ids.git)
    cd neuro-sentinel-ids
    ```

2.  **Build the Infrastructure**
    ```bash
    docker-compose build
    ```

3.  **Run the System**
    ```bash
    docker-compose up -d
    ```

4.  **Access the Dashboard**
    * Open your browser and navigate to `http://localhost:8501` (if using Streamlit).

---

## 📂 Project Structure

```text
neuro-sentinel-ids/
├── docker-compose.yml       # Orchestration file
├── README.md                # Documentation
├── ids_engine/              # Snort/Suricata Configuration
│   ├── Dockerfile
│   ├── snort.conf
│   └── rules/               # Custom rules (local.rules)
├── ml_engine/               # Python ML Logic
│   ├── Dockerfile
│   ├── inference.py         # Real-time log parser & predictor
│   ├── model.pkl            # Pre-trained model
│   └── requirements.txt
├── dashboard/               # Visualization App
│   └── app.py
└── attack_sim/              # Pentesting Tools
    └── Dockerfile
