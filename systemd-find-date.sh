#!/bin/bash

SYSTEMD_DIRS=(
  /etc/systemd/system
  /lib/systemd/system
  /usr/lib/systemd/system
)

echo "===================================================================================================="
echo "SERVICE NAME | RESTART | MODIFIED DATE | EXECSTART | FILE"
echo "===================================================================================================="

for dir in "${SYSTEMD_DIRS[@]}"; do
  [ -d "$dir" ] || continue

  find "$dir" -type f -name "*.service" 2>/dev/null | while read -r file; do
    restart=$(grep -E '^Restart=' "$file" | head -n1 | cut -d= -f2)

    # Filter Restart=always
    [[ "$restart" != "always" ]] && continue

    service_name=$(basename "$file")
    mod_date=$(stat -c '%y' "$file" 2>/dev/null | cut -d'.' -f1)

    # Extract FULL multiline ExecStart
    execstart=$(awk '
      /^\[Service\]/ {in_service=1}
      /^\[/ && !/^\[Service\]/ {in_service=0}
      in_service && /^ExecStart=/ {
        sub(/^ExecStart=/, "")
        line=$0
        while (line ~ /\\$/) {
          sub(/\\$/, "", line)
          getline nextline
          gsub(/^[ \t]+/, "", nextline)
          line=line nextline
        }
        print line
      }
    ' "$file")

    echo "----------------------------------------------------------------------------------------------------"
    echo "Service : $service_name"
    echo "Restart : $restart"
    echo "Date    : $mod_date"
    echo "Exec    : $execstart"
    echo "File    : $file"
  done
done
