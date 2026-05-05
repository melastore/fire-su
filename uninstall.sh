#!/bin/sh

FIRESU="/data/adb/modules/fire-su/system/bin/fire-su"
[ -x "$FIRESU" ] && "$FIRESU" disable

# remove configs
rm -rf /data/adb/fire-su

# clean our symlinks
rm -f /data/adb/ap/bin/fire-su
rm -f /data/adb/ksu/bin/fire-su
