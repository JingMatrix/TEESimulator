#!/system/bin/sh
# Arms TEESimulator on a system that is already up, by hand or from `ksud late-load`. Run it with
# --help for the options; everything it does lives in stage.sh.
exec sh "${0%/*}/stage.sh" late-load "$@"
