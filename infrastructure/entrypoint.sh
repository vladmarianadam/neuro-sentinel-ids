#!/bin/bash

# Update rules on startup (optional)
# ./update_rules.sh

echo "Starting Suricata on interface $IFACE..."

# Ensure log directory exists
mkdir -p /var/log/suricata

exec suricata -c /etc/suricata/suricata.yaml -i eth0