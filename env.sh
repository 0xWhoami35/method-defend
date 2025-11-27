for pid in /proc/[0-9]*; do
    pidnum=$(basename "$pid")
    name=$(cat "$pid/comm" 2>/dev/null)
    tr '\0' '\n' < "$pid/environ" 2>/dev/null \
        | grep -v '^$' \
        | sed "s/^/[PID $pidnum][$name] /"
done
