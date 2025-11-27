#!/usr/bin/env bash
# investigate-all-in-one-fixed.sh
# Grouped investigation tools with colored live Systemd Environment view (menu #9).
# Run as root for best results.

set -u
shopt -s nullglob

# Colors (use only when output is a terminal)
if [ -t 1 ]; then
  RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m')
  YELLOW=$(printf '\033[33m')
  BLUE=$(printf '\033[34m')
  CYAN=$(printf '\033[36m')
  BOLD=$(printf '\033[1m')
  NORMAL=$(printf '\033[0m')
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; NORMAL=""
fi

# Semantic colors per your request
SVC_COLOR="${GREEN}"   # service name => green
COMM_COLOR="${BLUE}"   # comm => blue
UID_COLOR="${RED}"     # uid => red
CMD_COLOR="${CYAN}"    # cmd => cyan

OUTDIR_DEFAULT="/root"
LOCKFILE="/dev/shm/.lock_investigate"

banner() {
  echo
  echo "${BLUE}${BOLD}=== $* ===${NORMAL}"
}

print_flag() {
  local lvl="$1"; shift
  local col
  case "$lvl" in
    danger) col="${RED}${BOLD}DANGER${NORMAL}";;
    suspicious) col="${YELLOW}${BOLD}SUSPICIOUS${NORMAL}";;
    safe) col="${GREEN}${BOLD}SAFE${NORMAL}";;
    info) col="${BLUE}${BOLD}INFO${NORMAL}";;
    *) col="${BOLD}$lvl${NORMAL}";;
  esac
  printf "%s %s\n" "$col" "$*"
}

# Utility: map UID -> user (if possible)
uid_to_user() {
  local uid="$1"
  local user
  user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || true)
  if [ -n "$user" ]; then
    printf '%s(%s)' "$uid" "$user"
  else
    printf '%s' "$uid"
  fi
}

# Utility: check if exe lives in standard system paths
is_standard_system_path() {
  local exe="$1"
  [[ "$exe" = /usr/bin/* || "$exe" = /usr/sbin/* || "$exe" = /bin/* || "$exe" = /sbin/* || "$exe" = /lib/* || "$exe" = /lib64/* ]]
}

# Utility: check if PID has network FDs (best-effort)
has_network_fds() {
  local pid="$1"
  if command -v lsof >/dev/null 2>&1; then
    # return 0 if any TCP/UDP shown
    lsof -nP -p "$pid" 2>/dev/null | awk 'NR>1 { if ($5 ~ /TCP|UDP/) exit 0 } END { exit 1 }'
    return $?
  else
    # fallback: look for 'socket:' in fd list
    ls -l "/proc/$pid/fd" 2>/dev/null | grep -qi socket && return 0 || return 1
  fi
}

################################################################################
# 1) find_user_sudo
################################################################################
# place this function near the other functions (before main/menu)
find_user_sudo() {
  banner "Users / groups with sudo privileges (best-effort, non-interactive)"

  echo
  # 1) Group members: sudo and wheel
  if getent group sudo >/dev/null 2>&1; then
    echo "[+] Group 'sudo' members:"
    getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' || true
  else
    echo "[+] Group 'sudo' not present"
  fi
  echo

  if getent group wheel >/dev/null 2>&1; then
    echo "[+] Group 'wheel' members:"
    getent group wheel | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' || true
  else
    echo "[+] Group 'wheel' not present"
  fi
  echo

  # 2) /etc/sudoers (non-comment lines)
  echo "[+] /etc/sudoers (non-comment lines):"
  if [ -r /etc/sudoers ]; then
    awk '!/^[[:space:]]*#/ && NF' /etc/sudoers 2>/dev/null || true
  else
    echo "  (no /etc/sudoers or unreadable)"
  fi
  echo

  # 3) /etc/sudoers.d (non-comment lines)
  echo "[+] /etc/sudoers.d (non-comment lines):"
  if ls /etc/sudoers.d/* 1>/dev/null 2>&1; then
    grep -hEv '^[[:space:]]*#|^[[:space:]]*$' /etc/sudoers.d/* 2>/dev/null || true
  else
    echo "  (no /etc/sudoers.d entries)"
  fi
  echo

  # 4) Try sudo -l for every local user non-interactively.
  # Use sudo -n (non-interactive) and redirect stdin from /dev/null so it doesn't prompt.
  echo "[+] Non-interactive check: sudo -n -lU <user> (shows users that MAY run commands)"
  while IFS=: read -r username _; do
    # Skip empty username lines if any
    [ -z "$username" ] && continue

    # run sudo -n -lU <user> redirecting stdin to avoid prompt stealing
    # If sudo is unavailable or returns non-zero, we skip quietly.
    if command -v sudo >/dev/null 2>&1 && sudo -n -lU "$username" < /dev/null 2>/dev/null | grep -q "may run"; then
      echo "  - $username"
    fi
  done < /etc/passwd
  echo

  # 5) Helpful summary if run as root: show which users are in sudo/wheel / listed explicitly
  if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    echo "[+] Quick summary (root):"
    echo -n "  Members of sudo: "
    getent group sudo 2>/dev/null | awk -F: '{print $4}' | sed 's/,/, /g' || echo "(none)"
    echo
    echo -n "  Members of wheel: "
    getent group wheel 2>/dev/null | awk -F: '{print $4}' | sed 's/,/, /g' || echo "(none)"
    echo
  fi

  echo
  echo "[+] Note: 'sudo -n' is non-interactive; some permission info may be hidden if passwords are required."
  echo "[+] If you want exhaustive interactive testing, run 'sudo -lU <username>' manually (it may prompt for password)."
  echo

  # pause but read from the terminal directly so the menu read afterwards works reliably
  read -r -p "Press ENTER to continue..." < /dev/tty
}



################################################################################
# 2) hidden_process_simple
################################################################################
hidden_process_simple() {
  banner "Simple interpreter/process scan (sh/bash/python/curl/wget)"
  for pidpath in /proc/[0-9]*; do
      PID=$(basename "$pidpath")
      CMD=$(tr '\0' ' ' < "$pidpath/cmdline" 2>/dev/null || true)
      EXE=$(readlink -f "$pidpath/exe" 2>/dev/null || true)
      if echo "$CMD $EXE" | grep -Eq "sh|bash|python|perl|php|curl|wget"; then
          echo "PID $PID: $CMD | $EXE"
      fi
  done
}

################################################################################
# 3) hidden_process_all
################################################################################
hidden_process_all() {
  banner "Full process scan (exe + cwd + cmdline) — saving bash/sshd to ${LOCKFILE}"
  : > "${LOCKFILE}" || true

  for pidpath in /proc/[0-9]*; do
      PID="${pidpath##*/}"

      CMDLINE=$(tr '\0' ' ' < "$pidpath/cmdline" 2>/dev/null || true)
      EXE=$(readlink -f "$pidpath/exe" 2>/dev/null || true)
      CWD=$(readlink -f "$pidpath/cwd" 2>/dev/null || true)

      [ -z "$CMDLINE" ] && continue
      [ -z "$EXE" ] && continue
      [ -z "$CWD" ] && continue

      owner="$(stat -c '%U' "$pidpath/exe" 2>/dev/null || true)"
      size_bytes="$(stat -c '%s' "$pidpath/exe" 2>/dev/null || true)"
      fd_count=$(ls -1 "$pidpath/fd" 2>/dev/null | wc -l 2>/dev/null || echo 0)

      reasons=()
      severity="safe"

      # Danger heuristics (corrected conditional usage)
      if [[ -n "$EXE" ]] && ( [[ "$EXE" == memfd:* ]] || [[ "$EXE" == *"(deleted)"* ]] ); then
        reasons+=("fileless/memfd or deleted exe")
        severity="danger"
      fi

      if echo "$EXE" | grep -Eq "^/dev/shm|/tmp/|/var/tmp/"; then
        reasons+=("running from tmp/shm")
        severity="danger"
      fi

      if has_network_fds "$PID"; then
        reasons+=("has network fds")
        [[ "$severity" != "danger" ]] && severity="suspicious"
      fi

      if [[ -n "$owner" && "$owner" != "root" ]]; then
        reasons+=("exe owner=$owner (non-root)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi

      if [[ "$size_bytes" =~ ^[0-9]+$ ]] && [ "$size_bytes" -gt 0 ] && [ "$size_bytes" -lt 51200 ]; then
        reasons+=("tiny exe (${size_bytes} bytes)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi

      if [ "$fd_count" -gt 100 ]; then
        reasons+=("many fds ($fd_count)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi

      if is_standard_system_path "$EXE" && [[ "$owner" == "root" ]] && [[ "$severity" == "safe" ]]; then
        reasons+=("likely system binary")
      fi

      case "$severity" in
        danger) print_flag danger "PID: $PID  EXE: $EXE" ;;
        suspicious) print_flag suspicious "PID: $PID  EXE: $EXE" ;;
        safe) print_flag safe "PID: $PID  EXE: $EXE" ;;
        *) echo "PID: $PID  EXE: $EXE" ;;
      esac

      echo "  CMDLINE: $CMDLINE"
      echo "  CWD:     $CWD"
      echo "  Owner:   ${owner:-?}    Size: ${size_bytes:-?} bytes   FDs: $fd_count"
      if [ ${#reasons[@]} -gt 0 ]; then
        echo "  Reasons: ${reasons[*]}"
      fi

      if ls -l "$pidpath/fd" 2>/dev/null | egrep -i 'memfd:|\-> /dev/shm|socket:|deleted' >/dev/null 2>&1; then
        echo "  Interesting fds:"
        ls -l "$pidpath/fd" 2>/dev/null | egrep -i 'memfd:|\-> /dev/shm|socket:|deleted' || true
      fi

      if echo "$EXE" | grep -Eq "/bash$|/sh$|/sshd$"; then
        {
          echo "PID: $PID"
          echo "CMDLINE: $CMDLINE"
          echo "EXE: $EXE"
          echo "CWD: $CWD"
          echo "--- LSOF ---"
          lsof -p "$PID" 2>/dev/null || echo "(lsof not available or permission denied)"
          echo "------"
        } >> "${LOCKFILE}" || true
      fi

      echo
  done

  print_flag info "Saved bash/sh/sshd lsof outputs to: ${LOCKFILE}"
}

################################################################################
# 4) running_deleted
################################################################################
running_deleted() {
  banner "Finding processes running deleted binaries or memfd-style in-memory images"
  for pidpath in /proc/[0-9]*; do
      PID=$(basename "$pidpath")
      EXE_RAW=$(readlink "$pidpath/exe" 2>/dev/null || true)
      if [[ -n "$EXE_RAW" ]] && ( [[ "$EXE_RAW" == memfd:* ]] || [[ "$EXE_RAW" == *"(deleted)"* ]] ); then
          print_flag danger "PID $PID: RUNNING A DELETED BINARY -> $EXE_RAW"
      fi
  done
}

################################################################################
# 5) systemd_binary_list
################################################################################
systemd_binary_list() {
  banner "Listing systemd services with MainPID, exe path and cmdline"
  while IFS= read -r S; do
      [ -z "$S" ] && continue
      PID=$(systemctl show -p MainPID --value "$S" 2>/dev/null || echo 0)
      if [[ "$PID" != "0" && -n "$PID" ]]; then
          EXE=$(readlink -f /proc/"$PID"/exe 2>/dev/null || true)
          CMDLINE=$(tr '\0' ' ' < /proc/"$PID"/cmdline 2>/dev/null || true)
          if [[ -z "$EXE" && -z "$CMDLINE" ]]; then
            continue
          fi
          if [[ "$EXE" == *"(deleted)"* || "$EXE" == memfd:* || "$EXE" == /dev/shm/* || "$EXE" == /tmp/* ]]; then
            print_flag danger "Unit: $S  PID: $PID  EXE: $EXE"
          else
            print_flag info "Unit: $S  PID: $PID  EXE: ${EXE:-(none)}"
          fi
          echo "  CMDLINE: $CMDLINE"
          echo
      fi
  done < <(systemctl list-units --type=service --all --no-legend | awk '{print $1}')
}

################################################################################
# 6) reap_zombies
################################################################################
reap_zombies() {
  FORCE=0
  if [ "${1:-}" = "force" ]; then
    FORCE=1
  fi

  banner "Reap/inspect zombie parents (interactive)"
  readarray -t PARENTS < <(ps -eo ppid,stat= | awk '$2~/Z/ {print $1}' | sort -u)

  if [ "${#PARENTS[@]}" -eq 0 ]; then
    echo "[+] No parents with zombie children found."
    return
  fi

  for P in "${PARENTS[@]}"; do
    [[ "$P" =~ ^[0-9]+$ ]] || continue
    [ "$P" -eq 0 ] && continue

    echo "--------------------------------------------------"
    print_flag info "Parent PID: $P"
    ps -o pid,ppid,stat,uid,user,cmd --pid "$P" || true
    echo "Cmdline: $(tr '\0' ' ' < /proc/$P/cmdline 2>/dev/null || true)"
    echo "Exe: $(readlink -f /proc/$P/exe 2>/dev/null || true)"
    echo "CWD: $(readlink -f /proc/$P/cwd 2>/dev/null || true)"

    ZCOUNT=$(ps -eo ppid,stat,pid | awk -v p="$P" '$1==p && $2~/Z/ {c++} END{print c+0}')
    print_flag info "Zombies for parent $P: $ZCOUNT"

    if [ "$ZCOUNT" -eq 0 ]; then
      continue
    fi

    if [ "$FORCE" -eq 1 ]; then
      yn="y"
    else
      read -rp "Attempt TERM then KILL parent $P? [y/N] " yn
    fi
    if [[ "$yn" =~ ^[Yy]$ ]]; then
      kill -TERM "$P" 2>/dev/null || true
      sleep 3
      if ps -p "$P" > /dev/null 2>&1; then
        kill -KILL "$P" 2>/dev/null || true
      fi
    fi
  done
  echo "Done."
}

################################################################################
# 7) dump_crontabs
################################################################################
dump_crontabs() {
  banner "Dumping system & user crontabs"
  echo "----- /etc/crontab -----"
  cat /etc/crontab 2>/dev/null || true
  echo
  echo "----- /etc/cron.d -----"
  ls -lah /etc/cron.d 2>/dev/null || true
  grep -R . /etc/cron.d 2>/dev/null || true
  echo
  echo "----- /etc/cron.hourly -----"
  ls -lah /etc/cron.hourly 2>/dev/null || true
  grep -R . /etc/cron.hourly 2>/dev/null || true
  echo
  echo "----- /etc/cron.daily -----"
  ls -lah /etc/cron.daily 2>/dev/null || true
  grep -R . /etc/cron.daily 2>/dev/null || true
  echo
  echo "----- Per-user crontabs -----"
  while IFS=: read -r u _; do
      echo "---- $u ----"
      crontab -u "$u" -l 2>/dev/null || echo "(no crontab)"
  done < /etc/passwd
}

################################################################################
# Helper for menu 9: get_unit_for_pid
################################################################################
get_unit_for_pid() {
  local pid="$1" unit last cg out unitline
  if [ -r "/proc/$pid/cgroup" ]; then
    unit=$(awk -F/ '/\.service|\.socket|\.scope/ {print $NF; exit}' "/proc/$pid/cgroup" 2>/dev/null || true)
    if [ -n "$unit" ]; then
      printf '%s' "$unit"
      return 0
    fi
    last=$(awk -F/ '{print $NF; exit}' "/proc/$pid/cgroup" 2>/dev/null || true)
    [ -n "$last" ] && unit="$last"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    out=$(systemctl status "$pid" 2>/dev/null || true)
    unitline=$(printf '%s\n' "$out" | sed -n '1p' || true)
    if printf '%s\n' "$unitline" | grep -q '\.service\|\.socket\|\.scope'; then
      unit=$(printf '%s\n' "$unitline" | awk '{print $2}' | tr -d '●' || true)
      [ -n "$unit" ] && { printf '%s' "$unit"; return 0; }
    fi
  fi

  printf '%s' "${unit:-}"
  return 0
}

################################################################################
# 9) systemd_environ (Group and color output)
################################################################################
systemd_environ() {
  banner "Systemd Envriont - grouped environment for systemd units"
  declare -A svc_seen
  for p in /proc/[0-9]*; do
    pid=${p##*/}
    [ -r "$p/environ" ] || continue

    unit=$(get_unit_for_pid "$pid")
    [ -z "$unit" ] && continue

    if [ -z "${svc_seen[$unit]+_}" ]; then
      echo -e "${SVC_COLOR}=== Service: $unit ===${NORMAL}"
      svc_seen[$unit]=1
    fi

    pname=$(head -n1 "$p/comm" 2>/dev/null || printf '?')
    uid_line=$(awk '/^Uid:/ {print $2; exit}' "$p/status" 2>/dev/null || true)
    uid_disp=$(uid_to_user "${uid_line:-?}")
    if [ -r "$p/cmdline" ]; then
      cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | sed 's/  */ /g;s/ $//')
    else
      cmd="$pname"
    fi
    [ -z "$cmd" ] && cmd="$pname"

    if ! mapfile -d $'\0' -t envs < "$p/environ" 2>/dev/null; then
      continue
    fi
    [ -d "/proc/$pid" ] || continue

    echo -e "  PID: $pid"
    echo -e "    comm: ${COMM_COLOR}$pname${NORMAL}"
    echo -e "    uid:  ${UID_COLOR}$uid_disp${NORMAL}"
    echo -e "    cmd:  ${CMD_COLOR}$cmd${NORMAL}"
    echo "    env:"
    for ev in "${envs[@]}"; do
      [[ -z "$ev" ]] && continue
      echo "      - $ev"
    done
    echo
  done
}

################################################################################
# Menu & main
################################################################################
print_menu() {
  cat <<EOF

${BOLD}${BLUE}INVESTIGATE - All-in-One (colorized)${NORMAL}
Run as root (recommended)
-------------------------------------------
  1) Find users with sudo/wheel & sudoers
  2) Simple interpreter/process scan (sh/bash/python/curl/wget)
  3) Full process scan (exe/cwd/cmdline) + save bash/sshd lsof -> ${LOCKFILE}
  4) Find running deleted/memfd binaries (danger)
  5) List systemd services and their MainPID/exe/cmdline
  6) Reap/inspect zombie parents (interactive)
  7) Dump system & user crontabs
  8) Run ALL checks and save to ${OUTDIR_DEFAULT}/investigate-ALL-<timestamp>.log
  9) Systemd Envriont (grouped colored environment dump for systemd units)
  0) Exit
-------------------------------------------
${NORMAL}
EOF
}

main() {
  while true; do
    print_menu
    read -rp "Choose an option: " choice
    case "$choice" in
      1) find_user_sudo; read -p "Press ENTER to continue..." ;;
      2) hidden_process_simple; read -p "Press ENTER to continue..." ;;
      3) hidden_process_all; read -p "Press ENTER to continue..." ;;
      4) running_deleted; read -p "Press ENTER to continue..." ;;
      5) systemd_binary_list; read -p "Press ENTER to continue..." ;;
      6) reap_zombies; read -p "Press ENTER to continue..." ;;
      7) dump_crontabs; read -p "Press ENTER to continue..." ;;
      8)
         OUT="${OUTDIR_DEFAULT}/investigate-ALL-$(date +%Y%m%dT%H%M%S).log"
         echo "[*] Running all checks — output -> $OUT"
         {
           echo "==== 1) find-user-sudo ====" ; find_user_sudo
           echo ; echo "==== 2) hidden-process-simple ====" ; hidden_process_simple
           echo ; echo "==== 3) hidden-process-all ====" ; hidden_process_all
           echo ; echo "==== 4) running-deleted ====" ; running_deleted
           echo ; echo "==== 5) systemd-binary-list ====" ; systemd_binary_list
           echo ; echo "==== 6) reap-zombies (non-forced) ====" ; reap_zombies
           echo ; echo "==== 7) dump-crontabs ====" ; dump_crontabs
           echo ; echo "==== 9) systemd-environ ====" ; systemd_environ
         } > "$OUT" 2>&1 || true
         echo "[*] All done. Report: $OUT"
         read -p "Press ENTER to continue..." ;;
      9) systemd_environ; read -p "Press ENTER to continue..." ;;
      0) echo "Bye."; exit 0 ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

main
