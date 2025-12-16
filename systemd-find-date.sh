#!/bin/bash

SYSTEMD_DIRS=(
  /etc/systemd/system
  /lib/systemd/system
  /usr/lib/systemd/system
)

printf "%-45s | %-20s | %-10s | %-25s | %s\n" \
  "SERVICE NAME" "RESTART" "DATE" "EXECSTART" "FILE"
printf "%0.s-" {1..160}
echo

for dir in "${SYSTEMD_DIRS[@]}"; do
  [ -d "$dir" ] || continue

  find "$dir" -type f -name "*.service" 2>/dev/null | while read -r file; do
    # Extract values
    execstart=$(grep -E '^ExecStart=' "$file" | head -n1 | cut -d= -f2-)
    restart=$(grep -E '^Restart=' "$file" | head -n1 | cut -d= -f2)

    # Filter only Restart=always
    if [[ "$restart" == "always" ]]; then
      service_name=$(basename "$file")
      mod_date=$(stat -c '%y' "$file" 2>/dev/null | cut -d'.' -f1)

      printf "%-45s | %-20s | %-10s | %-25s | %s\n" \
        "$service_name" \
        "$restart" \
        "$mod_date" \
        "${execstart:0:25}" \
        "$file"
    fi
  done
done
