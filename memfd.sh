for p in /proc/[0-9]*; do
  [[ -e "$p" ]] || continue
  pid=${p##*/}
  exe=$(readlink -f /proc/$pid/exe 2>/dev/null || true)
  if echo "$exe" | grep -qi memfd; then
    echo "memfd process: PID $pid -> $exe  cmd: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
  fi
done
