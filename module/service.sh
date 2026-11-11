#!/system/bin/sh
# The boot stage: a shim, like every other stage script here. init reaches this trigger after
# /data is mounted and the framework is starting, which is the earliest point the control daemon
# can do anything — what it does, and why there is no post-fs-data stage, is in stage.sh.
exec sh "${0%/*}/stage.sh" service
