# Neuro-Sentinel IDS/IPS

A hybrid Intrusion Detection and Prevention System combining **Suricata** (signature-based detection) with **Machine Learning** (anomaly-based detection) for comprehensive network security.

## Overview

Neuro-Sentinel uses a dual-layer approach to detect and block network threats:

1. **Signature-Based Detection** (Suricata): Detects known attack patterns using rule-based matching
2. **Anomaly-Based Detection** (ML Engine): Detects unknown/zero-day attacks using a Random Forest classifier trained on the NSL-KDD dataset

### Key Features

- Real-time network traffic analysis
- Automatic IP blocking via iptables (IPS mode)
- 98.56% detection accuracy on NSL-KDD benchmark
- Connection state tracking for advanced attack detection
- Web dashboard for monitoring alerts and traffic
- Built-in attack simulation environment for testing

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Traffic                               │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Suricata IDS (suricata_ids)                     │
│                   - Packet capture & inspection                      │
│                   - Signature-based detection                        │
│                   - Generates eve.json logs                          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ eve.json
┌─────────────────────────────────────────────────────────────────────┐
│                    ML Engine (ml_ips_brain)                         │
│                   - Real-time log analysis                           │
│                   - KDD-trained Random Forest model                  │
│                   - Connection state tracking                        │
│                   - Automatic IP blocking (iptables)                 │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Dashboard (security_dashboard)                     │
│                   - Real-time alert visualization                    │
│                   - Traffic monitoring                               │
│                   - System status                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
neuro-sentinel-ids/
├── docker-compose.yml          # Container orchestration
├── .env                        # Environment configuration
├── README.md                   # This file
│
├── infrastructure/             # Suricata IDS configuration
│   ├── Dockerfile
│   ├── suricata.yaml          # Suricata configuration
│   └── rules/                 # Detection rules
│       └── suricata.rules
│
├── ml_engine/                  # Machine Learning IPS
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── real_time_inference.py # Main inference engine
│   ├── train_model_kdd.py     # KDD dataset training script
│   ├── train_model_eve.py     # EVE JSON training script
│   ├── test_inference.py      # Unit tests
│   ├── models/                # Trained model artifacts
│   │   ├── kdd_model.joblib
│   │   ├── kdd_scaler.joblib
│   │   ├── kdd_encoders.joblib
│   │   └── kdd_feature_columns.joblib
│   └── datasets/              # Training data
│       ├── csv/               # NSL-KDD dataset
│       ├── all_bad_trafic/    # Malicious EVE JSON samples
│       └── pacap/             # PCAP files
│
├── dashboard/                  # Streamlit web UI
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
│
└── logs/                       # Shared log directory
    └── eve.json               # Suricata event log
```

## Requirements

- Docker & Docker Compose
- Linux host (for iptables IPS functionality)
- Python 3.9+ (for offline model training)
- Minimum 4GB RAM recommended

## Quick Start

### 1. Clone and Configure

```bash
cd neuro-sentinel-ids

# Check/edit environment configuration
cat .env
```

### 2. Train the ML Model (Optional - pre-trained model included)

```bash
cd ml_engine

# Install dependencies
pip install -r requirements.txt

# Train on NSL-KDD dataset (125,973 samples, 98.56% accuracy)
python train_model_kdd.py

# Or train on EVE JSON data
python train_model_eve.py
```

### 3. Start the System

```bash
# Build and start all containers
docker-compose up --build -d

# Verify all services are running
docker-compose ps
```

### 4. Access the Dashboard

Open your browser and navigate to: **http://localhost:8501**

### 5. Monitor Logs

```bash
# ML Engine logs (detections & blocks)
docker logs -f ml_ips_brain

# Suricata logs (signature alerts)
docker logs -f suricata_ids

# All services
docker-compose logs -f
```

## Testing the System

The project includes a Kali Linux container (`red_team_sim`) for attack simulation.

### Enter the Attacker Container

```bash
docker exec -it red_team_sim bash
```

### Test 1: Port Scanning (Probe Attack)

Port scans are used to discover open services on a target.

```bash
# Basic TCP SYN scan
nmap -sS victim_apache

# Aggressive scan with service detection
nmap -A victim_apache

# Scan multiple targets
nmap -sS victim_apache victim_ssh_server victim_nginx_server

# UDP scan
nmap -sU --top-ports 100 
```

**Expected Detection:**
- Suricata: `ET SCAN` signatures
- ML Engine: High `count` + high `diff_srv_rate` = Probe attack

### Test 2: SYN Flood (DoS Attack)

SYN floods overwhelm a target with half-open connections.

```bash
# SYN flood on port 80
hping3 -S --flood -p 80 victim_apache

# SYN flood with random source IPs (spoofed)
hping3 -S --flood -p 80 --rand-source victim_apache

# Targeted SYN flood on SSH
hping3 -S --flood -p 22 victim_ssh_server
```

**Expected Detection:**
- Suricata: `ET DOS` signatures
- ML Engine: High `serror_rate` + abnormal `total_bytes` = DoS attack

### Test 3: SSH Brute Force (R2L Attack)

Attempts to guess SSH credentials.

```bash
# Using Hydra with common credentials
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://victim_ssh_server

# Quick test with small wordlist
hydra -l root -p admin,password,123456,root ssh://victim_ssh_server
```

**Expected Detection:**
- Suricata: `ET SCAN SSH` signatures
- ML Engine: Multiple failed connections = R2L attack pattern

### Test 4: HTTP Flood (Application DoS)

Overwhelm a web server with HTTP requests.

```bash
# Simple HTTP flood using hping3
hping3 --flood -p 80 victim_apache

# Using curl in a loop
while true; do curl -s http://victim_apache > /dev/null; done

# Multiple concurrent connections
for i in {1..100}; do curl -s http://victim_apache & done
```

**Expected Detection:**
- High `srv_count` to same service
- Abnormal `bytes_toclient` patterns

### Test 5: Ping Flood (ICMP DoS)

```bash
# ICMP flood
hping3 --icmp --flood victim_apache

# Ping of death (oversized packets)
hping3 --icmp -d 65000 victim_apache
```

**Expected Detection:**
- Suricata: ICMP-related alerts
- ML Engine: ICMP protocol anomalies

### Test 6: Web Vulnerability Scanning

```bash
# Install nikto if needed
apt-get update && apt-get install -y nikto

# Scan for web vulnerabilities
nikto -h http://victim_apache
nikto -h http://victim_nginx_server
```

**Expected Detection:**
- Suricata: `ET WEB_SERVER` and `ET SCAN` signatures
- ML Engine: Unusual HTTP request patterns

### Test 7: DNS Amplification Setup

```bash
# DNSvictim_apache queries (if DNS server available)
nmap -sU -p 53 --script dns-recursion victim_apache
```

## Verifying Detections

### Check ML Engine Detections

```bash
docker logs ml_ips_brain | grep -E "(ALERT|DETECTION|BLOCKING)"
```

### Check Blocked IPs

```bash
# On the host machine
sudo iptables -L INPUT -n | grep DROP
sudo iptables -L DOCKER-USER -n | grep DROP
```

### Check Suricata Alerts

```bash
# View recent alerts
docker exec suricata_ids cat /var/log/suricata/fast.log | tail -50

# Or check eve.json
cat logs/eve.json | jq 'select(.event_type=="alert")' | tail -20
```

## ML Model Details

### Training Data: NSL-KDD Dataset

| Metric | Value |
|--------|-------|
| Total Records | 125,973 |
| Normal Traffic | 67,343 (53.5%) |
| Attack Traffic | 58,630 (46.5%) |
| Features | 9 Selected Features |
| Test Accuracy | 98.56% |

### Attack Categories Detected

| Category | Examples | Detection Method |
|----------|----------|------------------|
| **DoS** | neptune, smurf, pod, teardrop | High error rates, abnormal byte counts |
| **Probe** | satan, ipsweep, portsweep, nmap | High connection count, varied services |
| **R2L** | guess_passwd, ftp_write, warezclient | Failed login patterns |
| **U2R** | buffer_overflow, rootkit, perl | Privilege escalation indicators |

### Top Detection Features

| Feature | Importance | Description |
|---------|------------|-------------|
| src_bytes | 45.5% | Bytes from source |
| dst_bytes | 24.1% | Bytes to destination |
| same_srv_rate | 10.2% | Frequency of same service access |
| count | 6.1% | Connections to same host (2s window) |
| diff_srv_rate | 5.3% | Different services accessed |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_FILE_PATH` | `/var/log/suricata/eve.json` | Suricata log path |
| `BLOCK_THRESHOLD` | `0.85` | ML detection threshold |
| `MIN_BYTES_FOR_ANALYSIS` | `0` | Minimum bytes to analyze flow |

### Adjusting Detection Sensitivity

Edit `docker-compose.yml`:

```yaml
ml_engine:
  environment:
    - BLOCK_THRESHOLD=0.80       # Lower = more sensitive (more false positives)
    - MIN_BYTES_FOR_ANALYSIS=0   # 0 = analyze all flows (including empty SYN packets)
```

## Troubleshooting

### No Alerts Showing

1. Check if Suricata is capturing traffic:
   ```bash
   docker logs suricata_ids
   ```

2. Verify the network bridge exists:
   ```bash
   docker network ls | grep attack_net
   ip link show br-proiect
   ```

3. Check if eve.json is being written:
   ```bash
   ls -la logs/eve.json
   tail -f logs/eve.json
   ```

### ML Engine Not Blocking

1. Verify model is loaded:
   ```bash
   docker logs ml_ips_brain | grep "Model loaded"
   ```

2. Check iptables permissions:
   ```bash
   docker exec ml_ips_brain iptables -L
   ```

3. Ensure host networking is working:
   ```bash
   docker inspect ml_ips_brain | grep NetworkMode
   ```

### Dashboard Not Loading

1. Check container status:
   ```bash
   docker logs security_dashboard
   ```

2. Verify port binding:
   ```bash
   docker port security_dashboard
   netstat -tlnp | grep 8501
   ```

## Stopping the System

```bash
# Stop all containers
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Remove blocked IPs (on host)
sudo iptables -F INPUT
sudo iptables -F DOCKER-USER
```

## Re-training the Model

To train with new data:

```bash
cd ml_engine

# Binary classification (Normal vs Attack)
python train_model_kdd.py --labels binary

# Multi-class (Normal, DoS, Probe, R2L, U2R)
python train_model_kdd.py --labels category

# Using network-compatible features only
python train_model_kdd.py --features network
```

## License

This project is for educational and research purposes.

## References

- [NSL-KDD Dataset](https://github.com/HoaNP/NSL-KDD-DataSet/tree/master) 
- [Suricata Documentation](https://suricata.readthedocs.io/)
