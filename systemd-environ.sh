#!/usr/bin/env bash
shopt -s nullglob

for p in /proc/[0-9]*; do
    pid=${p##*/}
    envf="$p/environ"
    cgroupf="$p/cgroup"

    # must be readable
    [ -r "$envf" ] || continue

    # extract service name from cgroup
    service=$(awk -F/ '/\.service/ {print $NF}' "$cgroupf" 2>/dev/null | head -n1)

    # skip if not a systemd service
    [ -z "$service" ] && continue

    # read environment as null-separated, buffer it
    if ! mapfile -d $'\0' -t envs < "$envf" 2>/dev/null; then
        continue
    fi

    # verify process still exists
    [ -d "/proc/$pid" ] || continue

    # print output
    for ev in "${envs[@]}"; do
        [[ -z "$ev" ]] && continue
        printf '[PID %s][%s] %s\n' "$pid" "$service" "$ev"
    done
done
