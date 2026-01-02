FROM ubuntu:22.04

# Install Suricata
RUN apt-get update && apt-get install -y \
    suricata \
    && apt-get clean

# Copy your local config into the image
COPY suricata.yaml /etc/suricata/suricata.yaml