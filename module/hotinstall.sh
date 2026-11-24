#!/system/bin/sh
# A shim: the rules live in stage.sh. ksud runs the script customize.sh names in
# MODULE_HOT_RUN_SCRIPT, with no arguments, so the stage name needs a file of its own.
case $0 in */*) d=${0%/*} ;; *) d=. ;; esac
exec sh "$d/stage.sh" hotinstall
