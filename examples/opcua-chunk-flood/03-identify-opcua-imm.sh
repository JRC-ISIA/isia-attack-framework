#!/bin/bash
SCRIPT_DIR="$(dirname "$0")"
for f in "$SCRIPT_DIR/results/opcua_dump*"; do grep "ImmType" $f > /dev/null  && head -n1 $f;  done > "$SCRIPT_DIR/results/opcua_imm_addrs.txt"