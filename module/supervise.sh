#!/system/bin/sh
#
# The daemon's respawn loop, started detached by stage.sh (never run directly).
#
#   $1 = MODDIR (the module directory holding the daemon launcher and the per-ABI binaries)
#
# The first app_process of a boot can start before system_server is up, and the daemon then dies
# in the framework bootstrap; respawning it is what recovers. The loop is also the single-owner
# record: its pid file is how a later stage finds the daemon it has to stop, and clearing that
# file is how a stage tells the loop to stop instead of respawning — which also covers a SIGTERM
# that lands while the loop is waiting on its child rather than on the shell.
MODDIR=$1
PIDFILE=/data/adb/teesim/supervisor.pid

echo $$ >"$PIDFILE"
trap 'rm -f "$PIDFILE"; exit 0' TERM INT HUP

while true; do
  "$MODDIR/daemon" "$MODDIR"
  [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] || exit 0
  sleep 2
done
