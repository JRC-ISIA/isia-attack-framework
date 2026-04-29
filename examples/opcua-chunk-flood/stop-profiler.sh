#!/bin/bash
PLCS=("$@")
if [ ${#PLCS[@]} -eq 0 ]; then
    while IFS= read -r ip; do [ -n "$ip" ] && PLCS+=("$ip"); done
fi
[ ${#PLCS[@]} -eq 0 ] && { echo "Usage: $0 PLC_IP1 [PLC_IP2...] or cat plcs.txt | $0"; exit 1; }

for PLC_IP in "${PLCS[@]}"; do
    echo "=== $PLC_IP ==="
    SDM_URL="http://${PLC_IP}/sdm"
    OUTPUT="profiler_${PLC_IP}_$(date '+%Y%m%d_%H%M%S').pd"

    # Stop profiler
    echo "Stopping profiler on ${PLC_IP}..."
    curl -k -s "${SDM_URL}/svg.cgi?type=profiler&action=stop&size=1" -o /dev/null
done
echo "All PLCs stopped."


