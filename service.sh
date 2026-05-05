#!/system/bin/sh

FIRESU="/data/adb/modules/fire-su/system/bin/fire-su"
[ -x "$FIRESU" ] || FIRESU="/system/bin/fire-su"

log_msg() {
	echo "fire-su: $1" >/dev/kmsg
}

until [ "$(getprop sys.boot_completed)" = "1" ] && [ -f /data/system/packages.list ]; do
	sleep 1
done

if [ -x "$FIRESU" ]; then
	mkdir -p /data/adb/fire-su
	if "$FIRESU" status 2>/dev/null | grep -q "daemon=running"; then
		log_msg "eBPF daemon already running"
		exit 0
	fi
	echo "--- fire-su service start $(date +%s) ---" >>/data/adb/fire-su/fire-su.log
	"$FIRESU" daemon >>/data/adb/fire-su/fire-su.log 2>&1 &
	log_msg "eBPF daemon started"
else
	log_msg "command not found"
fi
