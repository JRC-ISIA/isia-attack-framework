cleanup(){
        if [[ -f run/logger.pid ]]; then
                kill "$(cat run/logger.pid)" 2>/dev/null || true
                rm -f run/logger.pid
		set -x echo deactivate
        fi
}
trap cleanup EXIT
