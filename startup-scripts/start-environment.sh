#!/usr/bin/env bash

cd "$(dirname "$0")"

source .venv/bin/activate

log_entry() {
    local module="$1"
    local level="$2"
    local message="$3"

    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")

    echo "${ts} [${module}] ${level}: ${message}"
}


export LCM_URI="${LCM_URI:-udpm://239.255.76.67:7667?ttl=16}"
export DEVICE_ID="${DEVICE_ID:-coord-pi01}"

mkdir -p run logs

if [ -f requirements.txt ]; then
        pip install -r requirements.txt > /dev/null 2>&1
fi

if ! [ -f logs/logger.out ]; then
       touche logs/logger.out
fi       

if [[ -f run/logger.pid ]]; then
	old_pid="$(cat run/logger.pid || true)"
	if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
		kill "${old_pid}" 2>/dev/null || true

	fi
	rm -f run/logger.pid
fi

nohup env PYTHONUNBUFFERED=1 python3 -u logger.py >> logs/logger.out 2>&1 &
echo $! > run/logger.pid
log_entry "Logger" "INFO" "logger.py started (pid $(cat run/logger.pid))" | tee >> logs/logger.out 
