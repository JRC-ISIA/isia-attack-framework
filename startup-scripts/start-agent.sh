#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f ../attack_client.py ]]; then
    printf 'ERROR: attack_client.py not found in ISIA-AF root directory. Call this script from ISIA-AF root directory.\n' "$PWD" >&2
    exit 1
fi


if [ ! -d ".venv" ]; then
	python3 -m venv .venv
fi

echo "[INFO] starting .venv"
source ../.venv/bin/activate
echo "[INFO] .venv started"

export LCM_URI="${LCM_URI:-udpm://239.255.76.67:7667?ttl=16}"
export DEVICE_ID="${DEVICE_ID:-attack-agent01}"

mkdir -p run logs

if [ -f requirements.txt ]; then
	echo "[INFO] installing requirements"
	python3 -m pip install -r requirements.txt || exit 1 
fi

cleanup(){
	if [[ -f run/attack_agent.pid ]]; then
		kill "$(cat run/attack_agent.pid)" 2>/dev/null || true
		rm -f run/attack_agent.pid
	fi
}
trap cleanup EXIT

python3 ../attack_client.py
