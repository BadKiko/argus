#!/usr/bin/env bash
# Automated Enter Key test — returns 0 if no Error dialog after submit.
set -euo pipefail
INSTALL=/usr/lib/beyondcompare
KEY_FILE=/tmp/bc_test_key.txt
cat > "$KEY_FILE" <<'EOF'
--- BEGIN LICENSE KEY ---
FAKE-ANY-KEY-12345-TEST
--- END LICENSE KEY -----
EOF

pkill -f '/usr/lib/beyondcompare/BCompare' 2>/dev/null || true
sleep 1
DISPLAY=${DISPLAY:-:1} "$INSTALL/run-BCompare.sh" >/dev/null 2>&1 &
sleep 8
WID=$(xdotool search --name 'Home - Beyond Compare' 2>/dev/null | head -1 || true)
if [ -z "$WID" ]; then echo "FAIL: no Home window"; exit 2; fi
xdotool windowactivate --sync "$WID"
sleep 0.3
xdotool key alt+h e
sleep 1.2
REG=$(xdotool search --name 'Register Beyond Compare' 2>/dev/null | head -1 || true)
if [ -z "$REG" ]; then echo "FAIL: no Register dialog"; exit 3; fi
xdotool windowactivate --sync "$REG"
sleep 0.3
eval "$(xdotool getwindowgeometry --shell "$REG")"
xdotool mousemove $((X + WIDTH/2)) $((Y + HEIGHT/2 + 30)) click 1
sleep 0.2
xdotool type --clearmodifiers --delay 2 --file "$KEY_FILE"
sleep 0.6
# dismiss clipboard sub-dialog if present
xdotool mousemove $((X + 520)) $((Y + 250)) click 1 2>/dev/null || true
sleep 0.5
xdotool key alt+o
sleep 2.5
if wmctrl -l | rg -qi 'Error'; then
  echo "FAIL: Error dialog visible"
  wmctrl -l | rg -i 'error|register|home|beyond'
  exit 1
fi
if wmctrl -l | rg -qi 'Register Beyond Compare'; then
  echo "FAIL: Register still open"
  exit 4
fi
echo "OK: no Error dialog, Register closed"
wmctrl -l | rg -i 'home|beyond|thanks|register|error' || true
exit 0
