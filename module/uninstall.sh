#!/system/bin/sh
# Run by the manager when the module is removed. Leaves the system carrying neither the daemon nor
# the interceptor; a no-op when the manager runs it at the next boot, where neither is up yet.
exec sh "${0%/*}/stage.sh" stop
