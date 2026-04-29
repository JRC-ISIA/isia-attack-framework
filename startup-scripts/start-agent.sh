#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
	python3 -m venv .venv
fi

echo "[INFO] starting .venv"
source .venv/bin/activate
echo "[INFO] .venv started"

export LCM_URI="${LCM_URI:-udpm://239.255.76.67:7667?ttl=16}"
export DEVICE_ID="${DEVICE_ID:-attack-agent01}"

mkdir -p run logs

if [ ! -d "tools" ]; then
	echo "[INFO] checking sha256sum on opcua-exploit.tar.gz data"
	if sha256sum -c "opcua-exploit.tar.gz.sha256" >/dev/null 2>&1; then
		echo "Success"
		mkdir -p tools
		tar -xzf "opcua-exploit.tar.gz" -C tools
	else
		echo "Checksum FAILED!" >&2
		exit 1
	fi
fi

if [ -f requirements.txt ]; then
	echo "[INFO] installing requirements"
	pip install -r requirements.txt >/dev/null 2>&1
fi

cleanup(){
	if [[ -f run/attack_agent.pid ]]; then
		kill "$(cat run/attack_agent.pid)" 2>/dev/null || true
		rm -f run/attack_agent.pid
	fi
}
trap cleanup EXIT

python3 attack_client.py
