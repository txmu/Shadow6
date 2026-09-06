#!/usr/bin/env bash
set -eu
umask 077
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
binary=${SHADOW6_GUARD_BIN:-"$script_dir/shadow6-guard"}
config=${SHADOW6_GUARD_CONFIG:-"$script_dir/config.json"}
pidfile=${SHADOW6_GUARD_PIDFILE:-"$script_dir/guard.pid"}
logfile=${SHADOW6_GUARD_LOGFILE:-"$script_dir/guard.log"}
process_start_time() {
    [ -r "/proc/$1/stat" ] || return 1
    stat_line=$(sed -n '1p' "/proc/$1/stat")
    stat_tail=${stat_line##*) }
    read -r -a stat_fields <<<"$stat_tail"
    [ "${#stat_fields[@]}" -ge 20 ] || return 1
    printf '%s\n' "${stat_fields[19]}"
}
read_pid() {
    [ -f "$pidfile" ] && [ ! -L "$pidfile" ] || return 1
    pid=$(sed -n '1p' "$pidfile")
    recorded_start=$(sed -n '2p' "$pidfile")
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    case "$recorded_start" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    current_start=$(process_start_time "$pid") || return 1
    [ "$current_start" = "$recorded_start" ] || return 1
    expected_binary=$(readlink -f -- "$binary") || return 1
    process_binary=$(readlink -f -- "/proc/$pid/exe") || return 1
    [ "$process_binary" = "$expected_binary" ] || return 1
    expected_config=$(readlink -f -- "$config") || return 1
    mapfile -d '' -t process_args <"/proc/$pid/cmdline" || return 1
    [ "${#process_args[@]}" -eq 3 ] || return 1
    [ "${process_args[1]}" = "--config" ] || return 1
    process_config=$(readlink -f -- "${process_args[2]}") || return 1
    [ "$process_config" = "$expected_config" ]
}
case ${1:-} in
    start)
        if read_pid; then echo "Already running (PID $pid)."; exit 0; fi
        [ ! -L "$pidfile" ] || { echo "Refusing symlink PID file: $pidfile" >&2; exit 1; }
        [ ! -L "$logfile" ] || { echo "Refusing symlink log file: $logfile" >&2; exit 1; }
        [ -x "$binary" ] || { echo "Missing executable: $binary" >&2; exit 1; }
        [ -f "$config" ] || { echo "Missing config: $config" >&2; exit 1; }
        nohup "$binary" --config "$config" >>"$logfile" 2>&1 </dev/null &
        pid=$!
        start_time=$(process_start_time "$pid") || {
            kill "$pid" 2>/dev/null || true
            echo "Could not verify started process." >&2
            exit 1
        }
        printf '%s\n%s\n' "$pid" "$start_time" >"$pidfile"
        echo "Started (PID $pid)."
        ;;
    stop)
        if ! read_pid; then rm -f -- "$pidfile"; echo "Not running."; exit 0; fi
        kill "$pid"
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
        if kill -0 "$pid" 2>/dev/null; then echo "Process did not stop cleanly." >&2; exit 1; fi
        rm -f -- "$pidfile"
        echo "Stopped."
        ;;
    status)
        if read_pid; then echo "Running (PID $pid)."; else echo "Not running."; exit 1; fi
        ;;
    *) echo "Usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
