#!/bin/bash
PLCS=("$@")

# Read from stdin if no args
if [ ${#PLCS[@]} -eq 0 ]; then
    while IFS= read -r ip; do
        [ -n "$ip" ] && PLCS+=("$ip")
    done
fi

if [ ${#PLCS[@]} -eq 0 ]; then
    echo "Usage: $0 PLC_IP1 [PLC_IP2 ...]  or  cat plcs.txt | $0"
    exit 1
fi

for PLC_IP in "${PLCS[@]}"; do
    echo "Starting profiler on ${PLC_IP}..."
    SDM_URL="http://${PLC_IP}/sdm"
    if curl -k -s "${SDM_URL}/svg.cgi?type=profiler&action=start&size=1" -o /dev/null; then
        echo "Started ${PLC_IP}"
    else
        echo "Failed ${PLC_IP}"
    fi
done
echo "Profilers started. Run stop_profiler.sh when ready."

