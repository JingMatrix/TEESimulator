#!/system/bin/sh
#
# Every stage the root managers can call, in one place. The module ships a one-line script per
# stage name — that is how a manager invokes them — and each forwards here.
#
#
# Who calls a stage, and what is running by the time they do
#
# Magisk, KernelSU and APatch all add the same init actions, and reach them in this order:
# post-fs-data (/data is mounted, the modules' post-fs-data.sh run, system.prop is loaded and the
# module set is mounted), zygote-start, nonencrypted (class_start late_start, then every module's
# service.sh, which nothing waits for), and sys.boot_completed=1 (ksud and apd run
# boot-completed.sh). The service command is hooked twice — under `on nonencrypted` and under
# `on property:vold.decrypt=trigger_restart_framework` — so a service stage must be safe to run
# twice, and the two can overlap. Every stage here therefore takes the lock below before it touches
# anything, and the second call then finds a daemon already running and does nothing.
#
# TEESimulator ships no post-fs-data.sh. Everything it does needs a running system: the daemon
# bootstraps a framework context, harvests from a real attested key, and injects into the keystore
# daemon. None of that exists at post-fs-data, and the module mounts nothing, so there is nothing
# to prepare that early. The boot path is service.sh alone.
#
# Two more entry points reach a system that is already up, both KernelSU's:
#
#   late-load    `ksud late-load` inserts the kernel module at runtime, applies sepolicy.rule and
#                the root profiles, then runs every module's late-load.sh against a 35 second
#                deadline shared with the stages that follow (the module mount, post-mount, and an
#                unwaited service). The same script is the one meant to be run by hand, which is
#                how a Magisk or APatch user arms the module after installing it without a reboot.
#
#   hotinstall   Requested from customize.sh with MODULE_HOT_INSTALL_REQUEST and
#                MODULE_HOT_RUN_SCRIPT. ksud moves the staged module directory over the live one,
#                applies its sepolicy.rule, enters init's mount namespace and runs the named
#                script with a 30 second deadline and stdin closed. Partition mounts, system.prop
#                and post-fs-data wait for the next boot, and no other stage runs — so whatever
#                has to happen for the new build to take over has to happen here.
#
# A stage reports to stdout, where whoever triggered it is looking: the KernelSU and APatch
# managers show the install log, and a hand-run late-load.sh prints to the shell. Two paths have
# nobody there at all — `ksud late-load` and the hot install it runs from its own daemon both
# discard the script's output — so every line also goes to logd under the TEESimulator tag, and
# from there into the daemon's own log and the WebUI's Logs panel, which is where a reader after
# the fact should look either way.
#
#
# What arming means here
#
# The daemon is the whole of it. It watches the keystore daemon and injects the interceptor into
# whatever pid it finds, so it never needed a boot stage to catch one — a running keystore is the
# normal case, not a special one. What differs on a running system is what that keystore process
# is already carrying: on a hot install it holds the PREVIOUS build's interceptor, which cannot be
# unloaded or injected over, so the daemon restarts the keystore service and injects the new one
# into the fresh process. That restart is the daemon's decision (it is the side that can tell its
# own current build from an older one); this script only says it is coming.
#
# SELinux: the module's sepolicy.rule is applied by the manager at post-fs-data, on a hot install,
# and on `ksud late-load`. A plain install followed by a hand-run late-load.sh is the one path
# where it has NOT been applied, and on an enforcing device the ptrace and socket denials that
# follow make the injection fail. Nothing here can load the policy, so the verdict below reports
# what actually happened rather than claiming success.

MODDIR=${0%/*}
DATA=/data/adb/teesim
# The supervisor's pid, under the daemon's own 0700 directory. Its FileObserver matches by name
# (config.json, overrides.json, *.xml), so a file here does not trip a re-resolve.
PIDFILE=$DATA/supervisor.pid
# Written when a hot install starts, so the daemon's own updater can tell the WebUI the build was
# applied without a reboot instead of asking for one. The updater deletes it before it flashes, so
# finding it afterwards means that install took this path.
HOT_MARKER=$DATA/hotinstall.pending
# The one stage at a time this module gets. A symlink is the lock because creating one is atomic
# and records its owner in the same step — a lock file written after the fact has a window where it
# is held by nobody, which is the whole bug this closes.
LOCK=$DATA/stage.lock
# The three waits a stage can spend, in seconds: on another stage finishing, on the previous daemon
# going down, and on the new one getting the interceptor into the keystore daemon. Their sum is
# what a hot install costs in the worst case, and it has to stay inside ksud's 30 second budget for
# that stage.
LOCK_TIMEOUT=5
STOP_TIMEOUT=8
ARM_TIMEOUT=12
# The grace a self-update gets before the old daemon is stopped: it is the process that asked for
# the install, and it still owes the WebUI a reply over the admin socket.
SELF_UPDATE_GRACE=3

STAGE=$1
[ -n "$STAGE" ] && shift

# A stage says everything twice: once on stdout, for whoever triggered it, and once into logd
# under the daemon's own tag. The second copy is not redundancy — `ksud late-load` and ksud's hot
# install throw the script's stdout away, so on the one path that matters most, a reboot arming the
# module with nobody at a shell, the first copy reaches no one. The daemon's log file and the
# WebUI's Logs panel both keep every TEESimulator line, which is where the header sends a reader
# after the fact. `log` is toybox on every supported device; where its domain cannot reach logd the
# write just fails, so nothing here depends on it.
emit() {
  echo "$1 teesim/$STAGE: $3"
  log -p "$2" -t TEESimulator "stage/$STAGE: $3" 2>/dev/null
}
say() { emit '-' i "$*"; }
warn() { emit '!' w "$*"; }

usage() {
  cat <<EOF
Usage: late-load.sh [--stop] [--help]

Arms TEESimulator on a system that is already running: starts the control daemon, which
harvests the device's attestation parameters and injects the interceptor into the running
keystore daemon. Run it after installing the module without a reboot.

  --stop   the reverse: stop the daemon and restart the keystore service, so the system is
           left carrying no interceptor at all.
  --help   this text.

The module's sepolicy.rule is only applied by the root manager at boot, on a hot install, and
on \`ksud late-load\`. After a plain install on an enforcing device, arming by hand can be
denied by SELinux; the verdict this prints says whether it worked.
EOF
}

# --- The situation ------------------------------------------------------------------------

# The keystore daemon's pid: keystore2 on Android 12+, keystore on 10/11. Only one of the two
# names exists on a device, and pidof prints nothing when neither is up.
keystore_pid() {
  for name in keystore2 keystore; do
    set -- $(pidof "$name" 2>/dev/null)
    if [ -n "$1" ]; then
      echo "$1"
      return 0
    fi
  done
  return 1
}

# Whether the keystore process carries an interceptor — ours or an older build's. Two shapes to
# match: the module's own libteesim_*.so, loaded straight from /data/adb, and the injector's
# staging fallback, which copies it to /data/local/tmp/lib<random>.so, dlopens that and unlinks
# it (so the map reads "(deleted)"). Exit 2 means the maps could not be read at all, which is a
# "cannot tell", not a "no" — and the read is attempted rather than tested, because root passes
# every permission test here and it is SELinux that refuses.
keystore_has_interceptor() {
  ks_maps=/proc/$1/maps
  cat "$ks_maps" >/dev/null 2>&1 || return 2
  grep -qE 'libteesim_|/data/local/tmp/lib' "$ks_maps" 2>/dev/null
}

# The inode of the interceptor mapped into $1, nothing when none is, and exit 2 when the maps
# cannot be read at all. Exit 2 is the same "cannot tell" as in keystore_has_interceptor.
mapped_interceptor_inode() {
  ks_maps=/proc/$1/maps
  cat "$ks_maps" >/dev/null 2>&1 || return 2
  set -- $(grep -m1 -E 'libteesim_|/data/local/tmp/lib' "$ks_maps" 2>/dev/null)
  echo "$5"
}

# The inode of the interceptor THIS build ships. It is the one fact that tells an interceptor the
# daemon has adopted — this build's, already in a keystore process that therefore never changed pid
# — from the previous build's, still sitting there with nothing having happened yet. Only the
# device's own ABI directory survives install, so the glob matches one file. Empty when stat is
# unavailable, which only costs the adopt case its early exit.
own_lib_inode() {
  for f in "$MODDIR"/*/libteesim_*.so; do
    [ -f "$f" ] || continue
    stat -c %i "$f" 2>/dev/null
    return
  done
}

# The supervisor's pid if the recorded one is still the loop we started, else nothing. A pid file
# outlives a reboot, so the pid is confirmed against the process behind it rather than trusted.
supervisor_pid() {
  sup_pid=$(cat "$PIDFILE" 2>/dev/null) || return 1
  case $sup_pid in
  '' | *[!0-9]*) return 1 ;;
  esac
  grep -q supervise.sh /proc/"$sup_pid"/cmdline 2>/dev/null || return 1
  echo "$sup_pid"
}

# The daemon itself, by the nice name it runs under. Its short-lived helper children are
# teesim-del and teesim-resign, which this name does not match. app_process takes that name a
# moment after it is spawned, so this can miss a daemon that has only just started — which is why
# the daemon is stopped through its supervisor's process group, not through this.
daemon_pids() { pidof teesim 2>/dev/null; }

# A respawn loop left behind by a build older than this one. Up to v4.0 the module ran
# `while true; do "$MODDIR/daemon"; sleep 2; done &` straight out of service.sh: no pid file, no
# record anywhere, and nothing but that shell knows it exists. Killing the daemon under such a loop
# only buys two seconds — it respawns one, now out of THIS build's directory, which then races the
# supervisor over the admin socket and injects the keystore daemon a second time. So an upgrade has
# to find those loops by the only trace they leave, the name of the script they are running, and
# stop them before the daemon. No stage of this build answers to that name: service.sh exec's
# stage.sh, so what shows in its cmdline is stage.sh.
# Only shells can be running it, and there are a handful of those against some 750 processes on a
# live phone — reading every /proc/pid/cmdline costs a fork each and took 1.2s on the device this
# was measured on, which is real money against a 30s hot-install budget. Each root manager runs
# module scripts through its own busybox, so the candidate names cover that as well as a plain
# /system/bin/sh.
legacy_loop_pids() {
  for p in $(pidof sh mksh ash dash bash busybox toybox 2>/dev/null); do
    [ "$p" = "$$" ] && continue
    # The trailing space is the argv terminator tr just rewrote, so this matches only a process
    # whose LAST argument is that script — the loop itself — and not a shell that merely mentions
    # the path, such as the one running a check like this.
    # stderr is redirected BEFORE the input: a process that exits between pidof and this read
    # makes the open fail, and the shell reports that itself, so stderr has to be gone already or
    # the complaint lands in the manager's install log.
    case $(tr '\0' ' ' 2>/dev/null </proc/"$p"/cmdline) in
    *"teesim/service.sh ") echo "$p" ;;
    esac
  done
}

# A process's group id (/proc/pid/stat field 5), read from after the last ')' so a comm holding
# spaces or parentheses cannot shift the fields.
process_pgid() {
  stat=$(cat /proc/"$1"/stat 2>/dev/null) || return 1
  set -- ${stat#*') '}
  echo "$3"
}

# --- The work directory -------------------------------------------------------------------

# admin.token is the WebUI's key-management credential; keep it root-only. The whole data dir
# holds the token and the admin socket, so keep it 0700 too — the socket is then unreachable to
# other apps. Also stage the WebUI's admin-socket client at a fixed, root-only path, so the WebUI
# can invoke it without knowing the module's runtime path or the device ABI. Only the device's own
# ABI directory survives install, so the glob matches one file; it is refreshed on every stage, so
# an update always stages the client that belongs to the build now installed.
prepare_data_dir() {
  mkdir -p "$DATA" 2>/dev/null
  chmod 0700 "$DATA" 2>/dev/null
  chmod 0600 "$DATA/admin.token" 2>/dev/null
  # Staged through a temp name and renamed, never written in place: the WebUI runs this very file
  # through the root bridge, and copying over a binary that a process is executing fails with
  # ETXTBSY — which, at boot, could not happen, and now can on every late-load and hot install. The
  # rename is atomic and leaves a running copy on its old inode, so an update always ends with the
  # client that belongs to the build now installed.
  for f in "$MODDIR"/*/teesim-uds; do
    if [ -f "$f" ]; then
      if cp "$f" "$DATA/teesim-uds.new" && chmod 0700 "$DATA/teesim-uds.new"; then
        mv -f "$DATA/teesim-uds.new" "$DATA/teesim-uds" || rm -f "$DATA/teesim-uds.new"
      else
        rm -f "$DATA/teesim-uds.new"
        warn "could not stage the WebUI's socket client; the WebUI keeps the one already there"
      fi
      break
    fi
  done
}

# --- One stage at a time ------------------------------------------------------------------

# Every stage here stops a daemon and starts another, and two doing that at once leave two
# supervisors with two daemons: they race over the admin socket, inject the keystore daemon twice,
# and the second one's pid file hides the first from every later stop. That is not hypothetical —
# init hooks the service command under two triggers, and a hand-run late-load.sh can land on top
# of either.
#
# A pid file cannot serialise this, because the pid in it belongs to a process that only exists
# after the check that reads it. `ln -s` can: creating a symlink is atomic, it fails when one is
# already there, and the owner's pid is its target, published in the same operation. Nothing ever
# follows the link, so a target that is not a path does not matter.
take_lock() {
  # The directory is normally the installer's doing, but a stage that cannot even take its lock
  # would report "another stage has it" for a directory that is simply missing.
  mkdir -p "$DATA" 2>/dev/null
  # Not the same thing as busy, and worth its own answer: a root shell can be uid 0 and still not
  # reach here. On KernelSU the kernel-side grant is what widens the capability bounding set, and
  # one that has not been applied yet leaves a shell with uid 0, no capabilities, and no way past
  # /data's permissions — under which every step below would fail and blame a stage that does not
  # exist.
  if [ ! -d "$DATA" ]; then
    warn "$DATA cannot be reached from here, so this stage can do nothing. A root shell that has"
    warn "uid 0 but no capabilities does this; check \`id\` and CapEff in /proc/self/status, and"
    warn "try again once the root manager has granted it properly."
    return 1
  fi
  i=0
  steals=0
  while :; do
    ln -s "$$" "$LOCK" 2>/dev/null && return 0

    # A stage killed by its manager's deadline leaves a lock nothing else will ever clean up, so
    # an owner that is no longer running loses it. An unreadable target is in that same class. The
    # steal is capped so that a lock being taken and dropped around us cannot spin here.
    owner=$(readlink "$LOCK" 2>/dev/null)
    dead=
    case $owner in
    '' | *[!0-9]*) dead=1 ;;
    *) [ -d /proc/"$owner" ] || dead=1 ;;
    esac
    if [ -n "$dead" ] && [ "$steals" -lt 3 ]; then
      steals=$((steals + 1))
      rm -f "$LOCK"
      continue
    fi

    i=$((i + 1))
    [ "$i" -ge "$LOCK_TIMEOUT" ] && break
    sleep 1
  done
  warn "another stage (pid ${owner:-?}) is already arming or disarming the module; leaving it to"
  warn "it rather than starting a second daemon"
  return 1
}

release_lock() { rm -f "$LOCK"; }

# --- Actions ------------------------------------------------------------------------------

# Starts the respawn loop, detached: a manager that reads a stage's output to EOF would otherwise
# wait out the whole session, and a hot install would spend its budget waiting for a daemon that
# is meant to outlive it. setsid is preferred for the clean session; backgrounding alone leaves it
# in the caller's process group, which is enough once stdio is gone, so a device without setsid
# still arms.
start_daemon() {
  # Every stage stops the previous loop before it starts one, so a pid file here belongs to a
  # concurrent stage — two hot installs seconds apart, say. Two daemons would race over the admin
  # socket and inject the keystore daemon twice, and the second loop's pid file would hide the
  # first from every later stop, so let the one already arming finish instead.
  if [ -n "$(supervisor_pid)" ]; then
    warn "another stage is already starting the daemon; leaving it to it"
    return 1
  fi

  if command -v setsid >/dev/null 2>&1; then
    setsid sh "$MODDIR/supervise.sh" "$MODDIR" </dev/null >/dev/null 2>&1 &
  else
    sh "$MODDIR/supervise.sh" "$MODDIR" </dev/null >/dev/null 2>&1 &
  fi
}

# Stops the loop and the daemon under it, and reports whether there was anything to stop.
#
# The pid file goes first, because that is the other thing the loop checks: one that misses the
# signal still finds the file is no longer its own when its child exits, and stops instead of
# respawning. A shell waiting on a foreground child may hold a trap until that child returns, so
# the loop is signalled through its PROCESS GROUP, which takes the daemon down in the same breath
# and needs no pid for it — but only once that group is proven to be the loop's own, because
# start_daemon falls back to a plain background job where the group is the caller's. `pidof` then
# sweeps up a daemon whose supervisor is already gone, or one an older build of this module left.
stop_daemon() {
  sup=$(supervisor_pid)
  legacy=$(legacy_loop_pids)
  # Taken before anything is signalled: a daemon that dies on the first SIGTERM would otherwise be
  # gone by the time this is read, and the stage would report that nothing had been running.
  running=$(daemon_pids)
  rm -f "$PIDFILE"
  [ -n "$legacy" ] && say "stopping the respawn loop an older build left running"
  signal_daemon TERM "$sup" $legacy
  [ -z "$running" ] && [ -z "$sup" ] && [ -z "$legacy" ] && return 1

  i=0
  while [ "$i" -lt "$STOP_TIMEOUT" ]; do
    alive=
    [ -n "$sup" ] && [ -d /proc/"$sup" ] && alive=1
    for p in $legacy; do [ -d /proc/"$p" ] && alive=1; done
    [ -n "$(daemon_pids)" ] && alive=1
    if [ -z "$alive" ]; then
      rm -f "$PIDFILE" # the loop rewrites it on the way out only if it raced us
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done

  # Whatever is left is holding the admin socket the next daemon needs to bind.
  signal_daemon KILL "$sup" $legacy
  warn "the previous daemon did not stop on SIGTERM and was killed"
  return 0
}

# Sends signal $1 to the supervisor $2 (by process group where it leads one, which takes its
# daemon child with it), to the older builds' respawn loops in $3.., and to every daemon process.
# The loops go first: one still alive when its daemon dies brings the daemon back.
signal_daemon() {
  sig=$1
  sup_target=$2
  shift 2
  for p in "$@"; do kill -"$sig" "$p" 2>/dev/null; done
  if [ -n "$sup_target" ]; then
    if [ "$(process_pgid "$sup_target")" = "$sup_target" ]; then
      kill -"$sig" -"$sup_target" 2>/dev/null
    else
      kill -"$sig" "$sup_target" 2>/dev/null
    fi
  fi
  for p in $(daemon_pids); do kill -"$sig" "$p" 2>/dev/null; done
}

# Asks init to restart the keystore service, which is what drops an interceptor already mapped
# into it — a library is never unloaded or injected over. Named for the device's own service, so
# this works on both generations.
restart_keystore() {
  for name in keystore2 keystore; do
    if [ -n "$(pidof "$name" 2>/dev/null)" ]; then
      setprop ctl.restart "$name"
      say "restarted the $name service"
      return 0
    fi
  done
  return 1
}

# Waits for the interceptor to reach the keystore daemon and reports the verdict. $1, when given,
# is a keystore pid that was ALREADY carrying one before the daemon started: a map that still shows
# that same process proves nothing, so it is waited out until either a new process appears (the
# daemon restarted the service to replace what was in there) or the budget runs out. The pid is
# re-read every round for the same reason — the process being watched can legitimately change.
report_arm() {
  stale=$1
  mine=$(own_lib_inode)
  i=0
  saw_keystore=
  while [ "$i" -lt "$ARM_TIMEOUT" ]; do
    pid=$(keystore_pid)
    if [ -n "$pid" ]; then
      saw_keystore=1
      ino=$(mapped_interceptor_inode "$pid")
      if [ $? = 2 ]; then
        say "armed; the keystore daemon's maps cannot be read here, so this cannot confirm the"
        say "interceptor reached it — the WebUI and the daemon's log can"
        return 0
      fi
      # A daemon has to be up for any of this to be its doing, and until one is there is nothing
      # to report either way.
      if [ -n "$ino" ] && [ -n "$(daemon_pids)" ]; then
        if [ "$pid" != "$stale" ]; then
          say "interceptor loaded into the keystore daemon (pid $pid)"
          return 0
        fi
        # Same process as before, carrying this build's own library: the daemon adopted what was
        # already in there instead of restarting the service, which is the quiet, cheap outcome
        # and the reason this stage does not wait for a new pid that is never coming.
        if [ -n "$mine" ] && [ "$ino" = "$mine" ]; then
          say "the keystore daemon (pid $pid) already carries this build's interceptor, and the"
          say "daemon adopted it rather than restarting the service"
          return 0
        fi
      fi
    fi
    sleep 1
    i=$((i + 1))
  done

  if [ -z "$saw_keystore" ] && [ -z "$stale" ]; then
    say "no keystore daemon is running, so there is nothing to inject into; the daemon takes"
    say "the next one that starts"
    return 0
  fi
  if [ -z "$(daemon_pids)" ]; then
    warn "the daemon is not running; its log is under $DATA/log"
    return 1
  fi
  if [ -n "$stale" ]; then
    say "the keystore daemon (pid $stale) still carries the interceptor it already had: the daemon"
    say "adopts that one when it is this build's and restarts the service when it is not, and its"
    say "log under $DATA/log says which it did"
    return 0
  fi
  warn "the daemon is up but the interceptor has not reached the keystore daemon in ${ARM_TIMEOUT}s"
  warn "(on an enforcing device, usually sepolicy.rule not applied yet, which a reboot fixes);"
  warn "the daemon's log under $DATA/log says which"
  return 1
}

# --- The stages ---------------------------------------------------------------------------

# The boot path, and the only stage a normal boot reaches. init hooks the service command twice
# (see the header), so an already-armed system is left alone rather than given a second daemon:
# two would race over the admin socket and inject the keystore daemon twice.
stage_service() {
  if [ -n "$(daemon_pids)" ]; then
    say "the daemon is already running; nothing to do"
    return 0
  fi
  prepare_data_dir
  start_daemon
  say "daemon started"
}

# Arms a system that is already up, whether `ksud late-load` got here or a root shell did. A
# daemon already running is replaced rather than left alone: this stage is only ever run to apply
# something, and the new daemon adopts a keystore daemon that already carries its own build, so
# re-arming costs a re-harvest and no keystore restart. ksud reaches its own service stage after
# this one returns, where the rule above makes service.sh a no-op.
stage_late_load() {
  if [ -f "$MODDIR/disable" ]; then
    warn "TEESimulator is marked disabled, arming it anyway because this stage was run"
  fi
  if [ -d /data/adb/modules/tricky_store ] && [ ! -f /data/adb/modules/tricky_store/disable ]; then
    warn "TrickyStore is installed and enabled; it hooks the same keystore path. Disable it and"
    warn "reboot, or the two will both be in there."
  fi

  stale=
  pid=$(keystore_pid)
  if [ -n "$pid" ] && keystore_has_interceptor "$pid"; then
    stale=$pid
    say "the running keystore daemon already carries an interceptor; the daemon adopts it when it"
    say "is this build's, and restarts the service to replace it when it is not"
  fi

  prepare_data_dir
  stop_daemon && say "stopped the previous daemon"
  start_daemon
  say "daemon started on a running system"
  report_arm "$stale"
}

# The new build is in place and nothing else will run. Stop the old daemon, start the new one, and
# say what the keystore daemon is about to go through: it carries the previous interceptor, so the
# new daemon restarts the service to get the new one in. Apps may see a transient keystore error
# as it goes down, which is the price of not rebooting.
stage_hotinstall() {
  if [ -f "$MODDIR/disable" ]; then
    say "TEESimulator is marked disabled, leaving this system as it is"
    return 0
  fi

  stale=
  pid=$(keystore_pid)
  if [ -n "$pid" ] && keystore_has_interceptor "$pid"; then
    stale=$pid
    say "the running keystore daemon carries the previous interceptor, so the daemon will"
    say "restart the service to load the new one; apps may see a transient keystore error"
  fi

  prepare_data_dir
  : >"$HOT_MARKER" 2>/dev/null

  # The daemon that asked for this install is the one being replaced, and it still owes the WebUI
  # the reply to that request over its admin socket. Hand the swap to a detached child and return,
  # so the reply goes out; the verdict is then the WebUI's to show, which is where that user is
  # looking anyway.
  if [ -n "$TEESIM_SELF_UPDATE" ]; then
    say "applying in the background so the update request can be answered first"
    if command -v setsid >/dev/null 2>&1; then
      setsid sh "$MODDIR/stage.sh" swap </dev/null >/dev/null 2>&1 &
    else
      sh "$MODDIR/stage.sh" swap </dev/null >/dev/null 2>&1 &
    fi
    return 0
  fi

  stop_daemon && say "stopped the previous daemon"
  start_daemon
  say "the new daemon is running"
  report_arm "$stale"
}

# The deferred half of a self-update's hot install (see stage_hotinstall). Detached from the
# caller, so it may outlive the stage that spawned it and take the old daemon down with it.
stage_swap() {
  sleep "$SELF_UPDATE_GRACE"
  stop_daemon
  start_daemon
}

# The reverse of arming, for `late-load.sh --stop` and for uninstall.sh. Stopping the daemon alone
# would leave the interceptor mapped in the keystore daemon with nothing driving it, so the service
# is restarted to drop it — but only when it is actually carrying one, which at the post-fs-data
# uninstall a manager usually runs it from is not yet the case.
stage_stop() {
  if stop_daemon; then
    say "stopped the daemon"
  else
    say "no daemon was running"
  fi

  pid=$(keystore_pid)
  if [ -n "$pid" ] && keystore_has_interceptor "$pid"; then
    say "the keystore daemon still carries the interceptor, which only a restart drops"
    restart_keystore
  else
    say "no interceptor is loaded in the keystore daemon; nothing to drop"
  fi
}

# --- Dispatch -----------------------------------------------------------------------------

stop_requested=
for arg in "$@"; do
  case $arg in
  -s | --stop) stop_requested=1 ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    warn "unknown option: $arg"
    usage
    exit 1
    ;;
  esac
done

if [ -n "$stop_requested" ]; then
  if [ "$STAGE" != "late-load" ]; then
    warn "--stop applies to the late-load stage only"
    exit 1
  fi
  STAGE=stop
fi

case $STAGE in
service | late-load | hotinstall | swap | stop) ;;
*)
  warn "unknown stage: ${STAGE:-<none>}"
  exit 1
  ;;
esac

# The lock is taken here rather than inside each stage so that every one of them has it, and
# released however the stage ends — including when its manager's deadline cuts it short, which
# otherwise leaves a lock behind for the staleness check to clear later.
take_lock || exit 0
# PIPE is in here for a reason: a stage whose reader goes away mid-sequence — a manager that stops
# reading the install log, a `| head` on a hand-run late-load — would otherwise be killed outright
# between stopping the old daemon and starting the new one, leaving the system disarmed and the
# lock behind. Trapped, the write fails and the stage finishes the job it started.
trap 'release_lock' EXIT HUP INT TERM PIPE

case $STAGE in
service) stage_service ;;
late-load) stage_late_load ;;
hotinstall) stage_hotinstall ;;
swap) stage_swap ;;
stop) stage_stop ;;
esac
rc=$?

# The self-update's deferred swap is the one child that outlives its stage, and it takes the lock
# itself when it wakes. Nothing else here leaves work behind.
exit $rc
