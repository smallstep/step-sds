#!/bin/sh

updateAlternatives() {
	update-alternatives --install /usr/bin/step-sds step-sds /usr/bin/step-sds 50
}

cleanInstall() {
	updateAlternatives
}

upgrade() {
	updateAlternatives
}

action="$1"
if [ "$1" = "configure" ] && [ -z "$2" ]; then
	action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
	action="upgrade"
fi

case "$action" in
	"1" | "install")
		cleanInstall
		;;
	"2" | "upgrade")
		upgrade
		;;
	*)
		cleanInstall
		;;
esac
