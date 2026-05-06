#!/usr/bin/env sh
set -eu

ROOT="${0%/*}"
[ "$ROOT" = "$0" ] && ROOT="."
OUT="$ROOT/fire-su.zip"

required="
META-INF/com/google/android/update-binary
META-INF/com/google/android/updater-script
module.prop
customize.sh
service.sh
action.sh
uninstall.sh
system/bin/fire-su
webroot/index.html
"

for path in $required; do
	if [ ! -e "$ROOT/$path" ]; then
		echo "missing required file: $path" >&2
		exit 1
	fi
done

rm -f "$OUT"

if command -v zip >/dev/null 2>&1; then
	(
		cd "$ROOT"
		zip -qr fire-su.zip \
			META-INF \
			module.prop \
			customize.sh \
			service.sh \
			action.sh \
			uninstall.sh \
			system \
			webroot \
			-x "*.DS_Store" \
			-x "__MACOSX/*"
	)
elif command -v bsdtar >/dev/null 2>&1; then
	(
		cd "$ROOT"
		bsdtar --exclude "*.DS_Store" --exclude "__MACOSX/*" -a -cf fire-su.zip \
			META-INF \
			module.prop \
			customize.sh \
			service.sh \
			action.sh \
			uninstall.sh \
			system \
			webroot
	)
elif command -v jar >/dev/null 2>&1; then
	(
		cd "$ROOT"
		jar cf fire-su.zip \
			META-INF \
			module.prop \
			customize.sh \
			service.sh \
			action.sh \
			uninstall.sh \
			system \
			webroot
	)
else
	echo "no zip writer found; install zip, bsdtar, or a JDK with jar" >&2
	exit 1
fi

echo "created $OUT"
