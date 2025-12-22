#!/bin/bash
echo "Fetching Emerging Threats Open Rules..."
suricata-update
# Copy generated rules to our mounted volume
cp /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/suricata.rules