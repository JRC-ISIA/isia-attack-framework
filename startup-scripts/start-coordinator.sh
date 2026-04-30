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

MODULES=("logger" "feature_extractor" "storage_transfer")

stop_module() {
    local name="$1"
    local pid_file="run/${name}.pid"
    if [[ -f "$pid_file" ]]; then
        local old_pid
        old_pid=$(cat "$pid_file")
        if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
            kill "${old_pid}" 2>/dev/null || true
        fi
        rm -f "$pid_file"
    fi
}

start_module() {
    local name="$1"
    local script="${name}.py"
    local pid_file="run/${name}.pid"
    local log_file="logs/${name}.out"

    stop_module "$name" # Clean up existing instance if any

    nohup env PYTHONUNBUFFERED=1 python3 -u "$script" >> "$log_file" 2>&1 &
    echo $! > "$pid_file"
    log_entry "${name^}" "INFO" "$script started (pid $(cat $pid_file))" | tee -a "$log_file" >> logs/coordinator.out
}

cleanup() {
    log_entry "Coordinator" "INFO" "Cleaning up background modules..."
    for mod in "${MODULES[@]}"; do
        stop_module "$mod"
    done
}
trap cleanup EXIT

if [ -f requirements.txt ]; then
    pip install -r requirements.txt > /dev/null 2>&1
fi

for mod in "${MODULES[@]}"; do
    start_module "$mod"
done

log_entry "Coordinator" "INFO" "coordinator.py starting with LCM_URI=${LCM_URI}" | tee -a logs/coordinator.out

python3 coordinator.py
