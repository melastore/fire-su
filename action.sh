#!/bin/sh
pm path io.github.a13e300.ksuwebui >/dev/null 2>&1 && {
	echo "- Launching WebUI in KSUWebUIStandalone..."
	am start -n "io.github.a13e300.ksuwebui/.WebUIActivity" -e id "fire-su"
	exit 0
}
pm path com.dergoogler.mmrl >/dev/null 2>&1 && {
	echo "- Launching WebUI in MMRL WebUI..."
	am start -n "com.dergoogler.mmrl/.ui.activity.webui.WebUIActivity" -e MOD_ID "fire-su"
	exit 0
}
echo "[!] Install KSU WebUI Standalone or MMRL for fire-su WebUI access"
sleep 2
am start -a android.intent.action.VIEW -d https://github.com/5ec1cff/KsuWebUIStandalone/releases
exit 0

# EOF
