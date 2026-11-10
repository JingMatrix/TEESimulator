#!/system/bin/sh
# A shim: the rules live in stage.sh, which a manager cannot call directly because it invokes the
# script customize.sh named in MODULE_HOT_RUN_SCRIPT.
exec sh "${0%/*}/stage.sh" hotinstall
