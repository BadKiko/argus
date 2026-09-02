#!/usr/bin/env bash
pkill -f 'argus-work/BCompare' 2>/dev/null || true
sleep 0.5
cd /usr/lib/beyondcompare || exit 1
echo "=== launch patched ==="
LD_LIBRARY_PATH='.argus-work:.' timeout 10 ./.argus-work/BCompare 2>/tmp/bc_err.txt
echo "patched exit=$?"
cat /tmp/bc_err.txt

echo "=== launch clean exe + patched SO ==="
# restore clean exe from install, keep patched SO
cp -f BCompare .argus-work/BCompare.clean_test 2>/dev/null
cp -f BCompare .argus-work/BCompare 2>/dev/null || cp -f /usr/lib/beyondcompare/BCompare .argus-work/BCompare
LD_LIBRARY_PATH='.argus-work:.' timeout 10 ./.argus-work/BCompare 2>/tmp/bc_err2.txt
echo "clean exe exit=$?"
cat /tmp/bc_err2.txt
