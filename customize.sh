CONFIG_DIR="/data/adb/fire-su"
OLD_CONFIG_DIR="/data/adb/net-switch"
ISOLATED="$CONFIG_DIR/isolated.json"
RULES="$CONFIG_DIR/rules.db"
SETTINGS="$CONFIG_DIR/settings.conf"
if [ ! -d "$(dirname "$ISOLATED")" ]; then
	mkdir -p "$(dirname "$ISOLATED")"
fi
if [ -f "$OLD_CONFIG_DIR/rules.db" ] && [ ! -f "$RULES" ]; then
	cp "$OLD_CONFIG_DIR/rules.db" "$RULES"
fi
if [ -f "$OLD_CONFIG_DIR/settings.conf" ] && [ ! -f "$SETTINGS" ]; then
	cp "$OLD_CONFIG_DIR/settings.conf" "$SETTINGS"
fi
if [ ! -f "$ISOLATED" ]; then
	echo "[]" >"$ISOLATED"
fi
[ -f "$RULES" ] || touch "$RULES"
[ -f "$SETTINGS" ] || echo "defaultMode=blacklist" >"$SETTINGS"
chmod 700 "$(dirname "$ISOLATED")" 2>/dev/null
chmod 600 "$ISOLATED" "$RULES" "$SETTINGS" 2>/dev/null

if [ "$KSU" = "true" ] || [ "$APATCH" = "true" ]; then
	# skip mount on APatch / KernelSU
	touch "$MODPATH/skip_mount"
	# symlink ourselves on $PATH
	manager_paths="/data/adb/ap/bin /data/adb/ksu/bin"
	for dir in $manager_paths; do
		if [ -d "$dir" ]; then
			echo "- creating symlink in $dir"
			ln -sf /data/adb/modules/fire-su/system/bin/fire-su "$dir/fire-su"
		fi
	done
fi

set_perm_recursive "$MODPATH/system" 0 0 0755 0755
set_perm_recursive "$MODPATH/webroot" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
