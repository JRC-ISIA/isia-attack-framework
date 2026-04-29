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
    sleep 3

    # Fetch data object list
    echo "Fetching data object list..."
    curl -k -s "${SDM_URL}/svg.cgi?type=profiler&action=content" -o /tmp/profiler_content.js

    # Extract timestamp from getIT() array: 'prfmod$f','2026-03-24 / 09:32:49'
    TIMESTAMP=$(grep -oP "prfmod\\\$f','\K[^']+" /tmp/profiler_content.js | head -1)
    rm -f /tmp/profiler_content.js

    if [ -z "$TIMESTAMP" ]; then
        echo "ERROR: No data object found on ${PLC_IP}. Debug output:"
        curl -k -s "${SDM_URL}/svg.cgi?type=profiler&action=content"
        echo ""
        continue
    fi

    echo "Timestamp found: $TIMESTAMP"

    # URL-encode timestamp for download URL
    ENCODED_TS=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$TIMESTAMP" 2>/dev/null)
    # Fallback if python3 not available
    if [ -z "$ENCODED_TS" ]; then
        ENCODED_TS=$(echo "$TIMESTAMP" | sed 's/ /%20/g; s|/|%2F|g; s/:/%3A/g')
    fi

    DOWNLOAD_URL="${SDM_URL}/cgiFileLoop.cgi?type=32&module=prfmod\$f&file=${ENCODED_TS}"
    echo "Downloading..."

    HTTP_CODE=$(curl -k -s -w "%{http_code}" "$DOWNLOAD_URL" -o "$OUTPUT")

    if [ "$HTTP_CODE" = "200" ]; then
        SIZE=$(du -h "$OUTPUT" | cut -f1)
        echo "Saved: $OUTPUT ($SIZE)"
    else
        echo "Download failed (HTTP $HTTP_CODE)"
        echo "URL tried: $DOWNLOAD_URL"
        rm -f "$OUTPUT"
    fi
    echo ""
done

echo "All PLCs done."

