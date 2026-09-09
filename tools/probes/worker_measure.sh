#!/bin/bash
# Phase 3.1 Step 12: remeasure the worker, reproducibly.
# The Phase 3 figures were taken once and never reproduced. This script is the
# reproduction: it is committed, so the numbers can be re-derived rather than
# recalled.
set -u
cd ~/projects/shadowfetch-4.0.0 || exit 1
SAMPLES=${1:-3}
WINDOW=${2:-20}
echo "host:    $(uname -srm)"
echo "cpu:     $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
echo "python:  $(python3 -V 2>&1)"
echo "commit:  $(git rev-parse --short HEAD)"
echo "samples: $SAMPLES x ${WINDOW}s idle window"
echo
CLK=$(getconf CLK_TCK)
for i in $(seq 1 "$SAMPLES"); do
  D=$(mktemp -d); mkdir -p "$D/state" "$D/ws"
  SHADOWFETCH_MISSIONS_STATE="$D/state" SHADOWFETCH_AGENT_WORKSPACES="$D/ws" \
    setsid timeout $((WINDOW + 12)) python3 \
    packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions worker \
    >/dev/null 2>&1 &
  sleep 5
  P=""
  for p in $(pgrep -f "shadowfetch-missions worker"); do
    if tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -q "$D"; then P=$p; break; fi
  done
  if [ -z "$P" ]; then echo "sample $i: worker not found"; rm -rf "$D"; continue; fi
  read -r _ _ _ _ _ _ _ _ _ _ _ _ _ U0 S0 _ < /proc/$P/stat
  V0=$(awk '/voluntary_ctxt_switches/{print $2; exit}' /proc/$P/status)
  N0=$(awk '/nonvoluntary_ctxt_switches/{print $2}' /proc/$P/status)
  W0=$(awk '/^syscw/{print $2}' /proc/$P/io 2>/dev/null || echo 0)
  B0=$(awk '/^write_bytes/{print $2}' /proc/$P/io 2>/dev/null || echo 0)
  sleep "$WINDOW"
  read -r _ _ _ _ _ _ _ _ _ _ _ _ _ U1 S1 _ < /proc/$P/stat
  V1=$(awk '/voluntary_ctxt_switches/{print $2; exit}' /proc/$P/status)
  N1=$(awk '/nonvoluntary_ctxt_switches/{print $2}' /proc/$P/status)
  W1=$(awk '/^syscw/{print $2}' /proc/$P/io 2>/dev/null || echo 0)
  B1=$(awk '/^write_bytes/{print $2}' /proc/$P/io 2>/dev/null || echo 0)
  TICKS=$(( (U1 - U0) + (S1 - S0) ))
  PCT=$(awk -v t="$TICKS" -v c="$CLK" -v w="$WINDOW" 'BEGIN{printf "%.4f", (t/c)/w*100}')
  echo "sample $i: cpu ${TICKS} ticks = ${PCT}% of a core | vol ctxt +$((V1-V0)) | nonvol +$((N1-N0)) | write syscalls +$((W1-W0)) | write_bytes +$((B1-B0))"
  kill -TERM "$P" 2>/dev/null; sleep 1; kill -KILL "$P" 2>/dev/null
  rm -rf "$D"
done
echo
echo "wake latency (queue a mission, time until the worker claims it):"
python3 - <<'PY'
import os, subprocess, sys, tempfile, time
from pathlib import Path
ENG = Path.home()/"projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENG))
d = tempfile.mkdtemp(); Path(d,"ws","probe").mkdir(parents=True); Path(d,"ws","probe","a.mkv").write_bytes(b"x")
os.environ.update(SHADOWFETCH_MISSIONS_STATE=d, SHADOWFETCH_AGENT_WORKSPACES=str(Path(d,"ws")))
import sf_missions as sf
s = sf.Store(d)
lat = []
for _ in range(5):
    w = sf.Wakeup(s.root) if hasattr(sf, "Wakeup") else None
    if w is None:
        print("  Wakeup class not found; skipping"); break
    t0 = time.monotonic()
    s.create(capability="media_export", provider_id="offline-media", workspace_value="probe",
             title="t", prompt="p", inputs=["a.mkv"])
    w.wait(5)
    lat.append(time.monotonic()-t0)
if lat:
    lat.sort()
    print("  n=%d  median %.4fs  max %.4fs" % (len(lat), lat[len(lat)//2], lat[-1]))
PY
