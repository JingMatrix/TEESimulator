#!/system/bin/sh
# Arms TEESimulator on a system that is already up, by hand or from `ksud late-load`. Run it with
# --help for the options; everything it does lives in stage.sh.
case $0 in */*) d=${0%/*} ;; *) d=. ;; esac # run as `sh late-load.sh` too
exec sh "$d/stage.sh" late-load "$@"
