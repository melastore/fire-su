#!/system/bin/sh

FIRESU="/data/adb/modules/fire-su/system/bin/fire-su"
[ -x "$FIRESU" ] || FIRESU="/system/bin/fire-su"
DIR="/data/adb/fire-su"
LOG="$DIR/fire-su.log"

log_msg() {
	echo "fire-su: $1" >/dev/kmsg
}

until [ "$(getprop sys.boot_completed)" = "1" ] && [ -f /data/system/packages.list ]; do
	sleep 1
done

if [ ! -x "$FIRESU" ]; then
	log_msg "command not found"
	exit 0
fi

mkdir -p "$DIR"
if "$FIRESU" status 2>/dev/null | grep -q "daemon=running"; then
	log_msg "eBPF daemon already running"
	exit 0
fi

# keep the previous boot's log for bug reports, drop anything older
[ -f "$LOG" ] && mv -f "$LOG" "$LOG.1"

# Restart after a crash so the firewall doesn't silently stay off. A clean
# exit (fire-su disable) ends the loop; five fast failures in a row give up.
(
	fails=0
	while [ "$fails" -lt 5 ]; do
		started=$(date +%s)
		echo "--- fire-su service start $started ---" >>"$LOG"
		"$FIRESU" daemon >>"$LOG" 2>&1 && break
		if [ $(($(date +%s) - started)) -lt 30 ]; then
			fails=$((fails + 1))
		else
			fails=0
		fi
		log_msg "eBPF daemon exited, restarting"
		sleep 3
	done
	[ "$fails" -ge 5 ] && log_msg "eBPF daemon keeps failing, see $LOG"
) &
log_msg "eBPF daemon started"
