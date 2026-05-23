#!/usr/bin/env bash
set -euo pipefail
ip="${1:-8.8.8.8}"
cd "$(dirname "$0")"
for cmd in "python3 intel.py" "node intel.js" "perl intel.pl" \
           "ruby intel.rb" "php -d memory_limit=1G intel.php" "lua intel.lua"; do
  bin="${cmd%% *}"
  if command -v "$bin" >/dev/null 2>&1; then
    exec $cmd "$ip"
  fi
done
echo "no supported runtime found (python3, node, perl, ruby, php, lua)" >&2
exit 1
