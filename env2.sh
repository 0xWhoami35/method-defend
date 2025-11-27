#!/bin/bash

echo "[+] Reading all /proc/*/environ …"
echo

for pid in /proc/[0-9]*; do
    pidnum=$(basename "$pid")

    # Skip if environ not readable
    if [ ! -r "$pid/environ" ]; then
        continue
    fi

    # Get process name
    if [ -f "$pid/comm" ]; then
        pname=$(cat "$pid/comm")
    else
        pname="unknown"
    fi

    echo "==============================="
    echo "PID: $pidnum"
    echo "Process: $pname"
    echo "-------------------------------"

    # Read environ and replace null bytes with line breaks
    tr '\0' '\n' < "$pid/environ"

    echo
done
