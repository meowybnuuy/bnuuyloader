#!/bin/bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

# One test cycle on the SM-T715: write an image to PARAM, check it, reboot, wait for Linux (by itself
# or after a forced restart), put the original PARAM back, then read S-Boot's log ring.
#   cycle.sh PARAM_IMAGE LABEL
# Writes PARAM only (the partition that holds logo.jpg, and with the kernel test the kernel itself,
# in the room of PARAM that S-Boot never reads); RECOVERY, BOOT and every other partition are never
# touched. Nothing is written unless the tablet answers and PARAM holds the original, or this image.
# The result is in out/cycles.log under [LABEL] and in dumps/sbootlog/seclog-LABEL.raw (read it with
# scripts/sbootlog.py, which masks the device identifiers the ring holds). Nothing identifying is
# logged here.
# Exit codes: 0 cycle complete, 1 nothing written, 2 missing file, 4 tablet not back within 35 minutes
#            (PARAM still holds the image), 6 original not back in PARAM.
set -u
IMG=$1; LABEL=$2
HERE=$(cd "$(dirname "$0")" && pwd)
T="${T715_TSSH:-}"
[ -n "$T" ] || T="$(cd "$HERE/"../../../.. && pwd)/omarchy-tab-s2/device/tssh" || true
ORIG="$HERE/../dumps/PARAM-mmcblk0p8.bin"
MODULE="$HERE/../tools/seclog_dump/seclog_dump.ko"
LOG="$HERE/../out/cycles.log"
DUMPS="$HERE/../dumps/sbootlog"
ORIG_SHA="${ORIG_SHA:?set ORIG_SHA to the SHA-256 of your own stock PARAM image}"
[ -x "$T" ] || { echo "tssh not found at $T"; exit 2; }
for f in "$IMG" "$ORIG" "$MODULE"; do [ -f "$f" ] || { echo "no file $f"; exit 2; }; done
mkdir -p "$HERE/../out" "$DUMPS"
log() { echo "$(date '+%H:%M:%S') [$LABEL] $*" | tee -a "$LOG"; }
up() { "$T" 'echo up' 2>/dev/null | grep -q up; }
param_sha() { "$T" 'sha256sum /dev/mmcblk0p8 | cut -c1-64' 2>/dev/null | tr -d '\r'; }
write_param() {   # $1 = a local image; prints the partition's sha256 afterwards
    cat "$1" | "$T" 'blockdev --setrw /dev/mmcblk0p8 && cat > /dev/mmcblk0p8 && sync && blockdev --setro /dev/mmcblk0p8 && sha256sum /dev/mmcblk0p8 | cut -c1-64' 2>/dev/null | tr -d '\r'
}

for i in 1 2 3 4 5 6; do up && break; sleep 5; done
up || { log "tablet not reachable over ssh: nothing written"; exit 1; }
LOCAL=$(shasum -a 256 "$IMG" | cut -c1-64)
BEFORE=$(param_sha)
case "$BEFORE" in
    "$ORIG_SHA"|"$LOCAL") ;;
    *) log "PARAM holds neither the original nor this image ($BEFORE): not writing"; exit 1;;
esac
GOT=$(write_param "$IMG")
[ "$GOT" = "$LOCAL" ] || { log "PARAM NOT verified (tablet $GOT, local $LOCAL): not rebooting"; exit 1; }
log "PARAM written and verified ($LOCAL)"

# the owner's rule (omarchy-tab-s2, docs/hardware/CPUFREQ.md 8.4): the modem's processor is off before
# any reboot into a test. Its boot programs eFuses, and must never be cut or run on an unstable kernel.
MODEM=$("$T" 'systemctl stop shannond.service shannon-loader.service 2>/dev/null; sleep 2; systemctl is-active shannond.service shannon-loader.service 2>&1 | tr "\n" " "' 2>/dev/null | tr -d '\r')
log "modem services: ${MODEM:-unknown} (inactive inactive wanted); reboot requested"
START=$(date +%s)
"$T" 'nohup sh -c "sleep 1; systemctl reboot" >/dev/null 2>&1' >/dev/null 2>&1
for i in $(seq 1 60); do sleep 5; up && break; done   # 300 s: the cpufreq test runs about 80 s
if up; then
    log "LINUX IS BACK by itself after $(( $(date +%s) - START )) s"
else
    log "NOT BACK after $(( $(date +%s) - START )) s: a forced restart is needed (Power + Volume Down about 10 s)"
    for i in $(seq 1 420); do sleep 5; up && break; done
    up || { log "tablet not back within 35 minutes: PARAM still holds this image"; exit 4; }
    log "tablet under Linux after the forced restart, after $(( $(date +%s) - START )) s"
fi
sleep 3

# the original goes back first, so that an unexpected restart cannot run the image a second time
BACK=$(write_param "$ORIG")
if [ "$BACK" = "$ORIG_SHA" ]; then log "ORIGINAL RESTORED AND VERIFIED"; else log "MISMATCH: the original is not back ($BACK)"; exit 6; fi

# what a kernel may have left of its last moments (ramoops), read at once: the next start would
# replace it.  Only read.
PSTORE="$HERE/../dumps/pstore/$LABEL"
mkdir -p "$PSTORE"
"$T" 'ls -la /sys/fs/pstore/' 2>/dev/null | tr -d '\r' | cut -c1-80 > "$PSTORE/_list" || true
for name in $("$T" 'ls /sys/fs/pstore/' 2>/dev/null | tr -d '\r'); do
    "$T" "cat /sys/fs/pstore/$name" > "$PSTORE/$name" 2>/dev/null
done
log "pstore: $(ls "$PSTORE" | grep -vc '^_' || true) record(s) read into dumps/pstore/$LABEL"

cat "$MODULE" | "$T" 'cat > /tmp/seclog_dump.ko' 2>/dev/null
"$T" 'insmod /tmp/seclog_dump.ko && dd if=/sys/kernel/debug/seclog_dump of=/tmp/seclog.raw bs=65536 2>/dev/null; rmmod seclog_dump; ls -la /tmp/seclog.raw | cut -c1-60' 2>&1 | tr -d '\r' | tee -a "$LOG"
"$T" 'cat /tmp/seclog.raw' > "$DUMPS/seclog-$LABEL.raw" 2>/dev/null
log "ring fetched: $(stat -f %z "$DUMPS/seclog-$LABEL.raw") bytes into dumps/sbootlog/seclog-$LABEL.raw (system: $("$T" 'systemctl is-system-running' 2>/dev/null | tr -d '\r'))"
exit 0
