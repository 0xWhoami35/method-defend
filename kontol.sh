#!/usr/bin/env bash
# investigate-all-in-one.sh (colorized)
# Run as root: sudo ./investigate-all-in-one.sh
set -euo pipefail

# Colors (use if stdout is a terminal)
if [ -t 1 ]; then
  RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m')
  YELLOW=$(printf '\033[33m')
  BLUE=$(printf '\033[34m')
  BOLD=$(printf '\033[1m')
  NORMAL=$(printf '\033[0m')
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; NORMAL=""
fi

OUTDIR_DEFAULT="/root"
LOCKFILE="/dev/shm/.lock"

banner() {
  echo
  echo "${BLUE}${BOLD}=== $* ===${NORMAL}"
}

# Helper to print a flagged message
print_flag() {
  local lvl="$1"; shift
  case "$lvl" in
    danger) col="${RED}${BOLD}DANGER${NORMAL}";;
    suspicious) col="${YELLOW}${BOLD}SUSPICIOUS${NORMAL}";;
    safe) col="${GREEN}${BOLD}SAFE${NORMAL}";;
    info) col="${BLUE}${BOLD}INFO${NORMAL}";;
    *) col="${BOLD}$lvl${NORMAL}";;
  esac
  printf "%s %s\n" "$col" "$*"
}

################################################################################
# Utilities used by multiple functions
################################################################################
has_network_fds() {
  local pid="$1"
  # return 0 if lsof shows any TCP/UDP for pid
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -p "$pid" 2>/dev/null | awk 'NR>1 && ($5 ~ /TCP|UDP/){exit 0} END{exit 1}'
  else
    # fallback: check /proc/<pid>/fd symlinks for socket: entries
    ls -l "/proc/$pid/fd" 2>/dev/null | grep -qi socket && return 0 || return 1
  fi
}

is_standard_system_path() {
  local exe="$1"
  [[ "$exe" = /usr/bin/* || "$exe" = /usr/sbin/* || "$exe" = /bin/* || "$exe" = /sbin/* || "$exe" = /lib/* || "$exe" = /lib64/* ]]
}

################################################################################
# 1) find-user-sudo
################################################################################
find_user_sudo() {
  banner "Users with sudo/wheel & sudoers"
  echo

  if getent group sudo >/dev/null; then
      echo "[+] Group 'sudo' members:"
      getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d'
  else
      echo "[+] No sudo group found"
  fi
  echo

  if getent group wheel >/dev/null; then
      echo "[+] Group 'wheel' members:"
      getent group wheel | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d'
  else
      echo "[+] No wheel group found"
  fi
  echo

  echo "[+] Users in /etc/sudoers:"
  grep -Ev '^#|^$' /etc/sudoers || true
  echo

  echo "[+] Users in /etc/sudoers.d/:"
  grep -hEv '^#|^$' /etc/sudoers.d/* 2>/dev/null || true
  echo

  echo "[+] Users with actual sudo privileges detected by 'sudo -l':"
  for u in $(cut -d: -f1 /etc/passwd); do
      if sudo -lU "$u" 2>/dev/null | grep -q "may run"; then
        echo "$u"
      fi
  done
  echo
}

################################################################################
# 2) hidden_process_simple
################################################################################
hidden_process_simple() {
  banner "Simple interpreter/process scan (sh/bash/python/curl/wget)"
  for pid in /proc/[0-9]*; do
      PID=$(basename "$pid")
      CMD=$(tr '\0' ' ' < "$pid/cmdline" 2>/dev/null || true)
      EXE=$(readlink -f "$pid/exe" 2>/dev/null || true)
      if echo "$CMD $EXE" | grep -qE "sh|bash|python|perl|php|curl|wget"; then
          echo "PID $PID: $CMD | $EXE"
      fi
  done
}

################################################################################
# 3) hidden_process_all (detailed, saves bash/sshd to /dev/shm/.lock)
################################################################################
hidden_process_all() {
  banner "Full process scan (exe + cwd + cmdline) — saving bash/sshd to ${LOCKFILE}"
  : > "${LOCKFILE}"

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

      # Build reasons and severity
      reasons=()
      severity="safe"

      # Danger heuristics
      if [[ "$EXE" == memfd:* || "$EXE" == *"(deleted)"* ]]; then
        reasons+=("fileless/memfd or deleted exe")
        severity="danger"
      fi
      if echo "$EXE" | grep -qE "^/dev/shm|/tmp/|/var/tmp/"; then
        reasons+=("running from tmp/shm")
        severity="danger"
      fi
      if has_network_fds "$PID"; then
        reasons+=("has network fds")
        # keep severity danger if already danger, else suspicious
        [[ "$severity" != "danger" ]] && severity="suspicious"
      fi

      # Suspicious heuristics
      if [[ -n "$owner" && "$owner" != "root" ]]; then
        reasons+=("exe owner=$owner (non-root)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi
      if [[ "$size_bytes" =~ ^[0-9]+$ ]] && [ "$size_bytes" -gt 0 ] && [ "$size_bytes" -lt 51200 ]; then
        reasons+=("tiny exe (${size_bytes} bytes)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi
      if [[ "$fd_count" -gt 100 ]]; then
        reasons+=("many fds ($fd_count)")
        [[ "$severity" == "safe" ]] && severity="suspicious"
      fi
      # interpreter/script mismatch
      if echo "$EXE" | grep -qE '/bin/(ba)?sh|/usr/bin/python|/usr/bin/perl|/usr/bin/php'; then
        scriptpath=$(echo "$CMDLINE" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\//) print $i}' | head -n1 || true)
        if [[ -n "$scriptpath" ]] && echo "$scriptpath" | grep -qE '(/dev/shm/|/tmp/|/var/tmp/)'; then
          reasons+=("interpreter launching script in tmp/shm: $scriptpath")
          [[ "$severity" == "safe" ]] && severity="suspicious"
        fi
      fi

      # If it's in regular system paths and owned by root, prefer safe
      if is_standard_system_path "$EXE" && [[ "$owner" == "root" ]] && [[ "$severity" == "safe" ]]; then
        reasons+=("likely system binary")
      fi

      # print header with color
      case "$severity" in
        danger) print_flag danger "PID: $PID  EXE: $EXE" ;;
        suspicious) print_flag suspicious "PID: $PID  EXE: $EXE" ;;
        safe) print_flag safe "PID: $PID  EXE: $EXE" ;;
        *) echo "PID: $PID  EXE: $EXE" ;;
      esac

      # print details
      echo "  CMDLINE: $CMDLINE"
      echo "  CWD:     $CWD"
      echo "  Owner:   ${owner:-?}    Size: ${size_bytes:-?} bytes   FDs: $fd_count"
      if [ ${#reasons[@]} -gt 0 ]; then
        echo "  Reasons: ${reasons[*]}"
      fi

      # show interesting fds
      if ls -l "$pidpath/fd" 2>/dev/null | egrep -i 'memfd:|\-> /dev/shm|socket:|deleted' >/dev/null 2>&1; then
        echo "  Interesting fds:"
        ls -l "$pidpath/fd" 2>/dev/null | egrep -i 'memfd:|\-> /dev/shm|socket:|deleted' || true
      fi

      # save full lsof to lockfile for bash/sh/sshd
      if echo "$EXE" | grep -qE "/bash$|/sh$|/sshd$"; then
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
# 4) running_deleted (memfd/deleted exe finder)
################################################################################
running_deleted() {
  banner "Finding processes running deleted binaries or memfd-style in-memory images"
  for pid in /proc/[0-9]*; do
      PID=$(basename "$pid")
      EXE_RAW=$(readlink "$pid/exe" 2>/dev/null || true)
      if [[ -n "$EXE_RAW" ]] && ([[ "$EXE_RAW" == memfd:* ]] || [[ "$EXE_RAW" == *"(deleted)"* ]]); then
          print_flag danger "PID $PID: RUNNING A DELETED BINARY -> $EXE_RAW"
      fi
  done
}

################################################################################
# 5) systemd_binary_list
################################################################################
systemd_binary_list() {
  banner "Listing systemd services with MainPID, exe path and cmdline"
  for S in $(systemctl list-units --type=service --all --no-legend | awk '{print $1}'); do
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
  done
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
  for u in $(cut -d: -f1 /etc/passwd); do
      echo "---- $u ----"
      crontab -u "$u" -l 2>/dev/null || echo "(no crontab)"
  done
}

################################################################################
# Menu
################################################################################
print_menu() {
  cat <<EOF

${BOLD}${BLUE}INVESTIGATE - All-in-One (colorized)${NORMAL}
Run as root (sudo)
-------------------------------------------
  1) Find users with sudo/wheel & sudoers
  2) Simple interpreter/process scan (sh/bash/python/curl/wget)
  3) Full process scan (exe/cwd/cmdline) + save bash/sshd lsof -> ${LOCKFILE}
  4) Find running deleted/memfd binaries (danger)
  5) List systemd services and their MainPID/exe/cmdline
  6) Reap/inspect zombie parents (interactive)
  7) Dump system & user crontabs
  8) Run ALL checks and save to ${OUTDIR_DEFAULT}/investigate-ALL-<timestamp>.log
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
         } > "$OUT" 2>&1
         echo "[*] All done. Report: $OUT"
         read -p "Press ENTER to continue..." ;;
      0) echo "Bye."; exit 0 ;;
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

main
