#!/bin/bash
SCRIPT_DIR="$(dirname "$0")"
mkdir "$SCRIPT_DIR/results"
OWN_IP=$(hostname -I | cut -f 1 -d ' ')
nmap -p 4840 "$OWN_IP/24" --exclude "$OWN_IP" -oG - | grep "Status: Up" | cut -f 2 -d ' ' > "$SCRIPT_DIR/results/opcua_active.txt"
