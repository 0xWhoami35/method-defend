#!/bin/bash

echo "Servicess with Restart=always (showing only ExecStart and Restart):"
echo "---------------------------------------------------------------------"

services=$(systemctl list-unit-files --type=service --no-legend | awk '{print $1}')

for svc in $services; do
    # Check if unit contains Restart=always
    if systemctl cat "$svc" --no-pager 2>/dev/null | grep -q "Restart=always"; then

        echo ""
        echo "==============================="
        echo "SERVICE: $svc"
        echo "==============================="

        # Print filtered lines (Restart=always and ExecStart)
        systemctl cat "$svc" --no-pager \
        | grep -E "^(ExecStart|Restart=always)"
    fi
done
