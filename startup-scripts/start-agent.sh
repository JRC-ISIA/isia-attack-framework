#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -f attack_client.py ]]; then
    printf 'ERROR: attack_client.py not found in directory %s\n' "$PWD" >&2
    exit 1
fi

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

export LCM_URI="${LCM_URI:-udpm://239.255.76.67:7667?ttl=16}"
export DEVICE_ID="${DEVICE_ID:-$(hostname)}"

mkdir -p run logs

if [ -f requirements.txt ]; then
    echo "[INFO] Installing requirements..."
    python3 -m pip install -r requirements.txt || true
fi

cleanup(){
    if [[ -f run/attack_agent.pid ]]; then
        kill "$(cat run/attack_agent.pid)" 2>/dev/null || true
        rm -f run/attack_agent.pid
    fi
}
trap cleanup EXIT

echo $$ > run/attack_agent.pid
echo "[INFO] Starting attack_client.py with LCM_URI=${LCM_URI} and DEVICE_ID=${DEVICE_ID}..."
python3 attack_client.py