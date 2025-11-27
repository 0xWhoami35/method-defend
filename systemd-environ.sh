#!/usr/bin/env bash
# LIVE OUTPUT with colors

set -u
shopt -s nullglob

# Colors
GREEN="\033[32m"
BLUE="\033[34m"
RED="\033[31m"
CYAN="\033[36m"
NC="\033[0m"

uid_to_user() {
  local uid="$1"
  local user
  user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || true)
  [ -n "$user" ] && printf '%s(%s)' "$uid" "$user" || printf '%s' "$uid"
}

declare -A svc_seen

for p in /proc/[0-9]*; do
  pid=${p##*/}
  envf="$p/environ"
  commf="$p/comm"
  cgroupf="$p/cgroup"
  statusf="$p/status"
  cmdf="$p/cmdline"

  [ -r "$envf" ] || continue

  # detect systemd unit
  service=$(awk -F/ '/\.service/ {print $NF; exit}' "$cgroupf" 2>/dev/null)
  [ -z "$service" ] && service="(no.service)"

  # print service header (in GREEN)
  if [ -z "${svc_seen[$service]+_}" ]; then
    echo -e "${GREEN}=== Service: $service ===${NC}"
    svc_seen[$service]=1
  fi

  # comm (dark blue)
  pname=$(head -n1 "$commf" 2>/dev/null || printf '?')

  # uid (red)
  uid_line=$(awk '/^Uid:/ {print $2; exit}' "$statusf" 2>/dev/null || true)
  uid_disp=$(uid_to_user "${uid_line:-?}")

  # cmdline (cyan)
  if [ -r "$cmdf" ]; then
    cmd=$(tr '\0' ' ' < "$cmdf" 2>/dev/null | sed 's/  */ /g;s/ $//')
  else
    cmd="$pname"
  fi
  [ -z "$cmd" ] && cmd="$pname"

  # read environment vars
  mapfile -d $'\0' -t envs < "$envf" 2>/dev/null || continue
  [ -d "/proc/$pid" ] || continue

  echo "  PID: $pid"
  echo -e "    comm: ${BLUE}$pname${NC}"
  echo -e "    uid:  ${RED}$uid_disp${NC}"
  echo -e "    cmd:  ${CYAN}$cmd${NC}"
  echo    "    env:"

  for ev in "${envs[@]}"; do
    [[ -z "$ev" ]] && continue
    echo "      - $ev"
  done

  echo
done
