#!/usr/bin/env bash
set -euo pipefail
pkill -f 'argus-work/BCompare' 2>/dev/null || true
sleep 1
cd /usr/lib/beyondcompare
LD_LIBRARY_PATH='.argus-work:.' ./.argus-work/BCompare >/dev/null 2>&1 &
sleep 6
WID=$(xdotool search --name 'Home - Beyond Compare' | head -1)
xdotool windowactivate --sync "$WID"
sleep 0.5
xdotool key Escape
sleep 0.2
xdotool key alt+h
sleep 0.6
xdotool key Down Down Down Return
sleep 1.5
cat > /home/kiko/petwork/argus/tmp_test_key.txt <<'EOF'
--- BEGIN LICENSE KEY ---
FAKE-ANY-KEY-12345
--- END LICENSE KEY -----
EOF
REG=$(xdotool search --name 'Register Beyond Compare' | head -1)
echo "REG=$REG"
xdotool windowactivate --sync "$REG"
sleep 0.4
eval "$(xdotool getwindowgeometry --shell "$REG")"
xdotool mousemove $((X + WIDTH / 2)) $((Y + HEIGHT / 2 - 30)) click 1
sleep 0.3
xclip -selection clipboard < /home/kiko/petwork/argus/tmp_test_key.txt
xdotool key ctrl+v
sleep 0.6
xdotool key alt+o
sleep 2
echo "WINDOWS:"
wmctrl -l | grep -iE 'error|register|home|beyond' || true
