#!/usr/bin/env bash
# Procurement driver — resumable, continue-on-error, background-safe.
#
#   data lives OUTSIDE the repo (too big to commit):   $BENCH_DATA  (default /home/opsclaw/bench_data)
#   durable state on disk so progress survives a crash: $BENCH_DATA/_ledger.tsv + per-dir .fetch_done
#   one failure never aborts the run — it is logged and the driver continues.
#
# usage:  scripts/fetch_all.sh            # fetch everything still pending
#         scripts/fetch_all.sh cybench    # fetch a single id
#         FORCE=1 scripts/fetch_all.sh id # re-fetch even if .fetch_done present
set -u
export PATH="$HOME/.local/bin:$PATH"   # pick up a user-local git-lfs if present

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${BENCH_DATA:-/home/opsclaw/bench_data}"
CATALOG="$REPO_DIR/catalog.tsv"
ONLY="${1:-}"
LOG="$DATA_DIR/_fetch.log"
LEDGER="$DATA_DIR/_ledger.tsv"
mkdir -p "$DATA_DIR"

log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG" >&2; }
dirsize(){ du -sh "$1" 2>/dev/null | awk '{print $1}'; }

[ -f "$LEDGER" ] || printf 'id\tstatus\tsha\tsize\tts\tnote\n' > "$LEDGER"
set_ledger(){ # id status sha size note
  grep -vP "^$1\t" "$LEDGER" > "$LEDGER.tmp" 2>/dev/null || true
  mv -f "$LEDGER.tmp" "$LEDGER" 2>/dev/null || true
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(date -u +%FT%TZ)" "$5" >> "$LEDGER"
}

fetch_git(){ # id url sha
  local id="$1" url="$2" sha="$3" dest="$DATA_DIR/$1"
  if [ -z "${FORCE:-}" ] && [ -f "$dest/.fetch_done" ]; then log "SKIP $id (done)"; return 0; fi
  rm -rf "$dest"
  log "GIT  $id <- $url"
  if GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --quiet "$url" "$dest" 2>>"$LOG"; then
    command -v git-lfs >/dev/null 2>&1 && ( cd "$dest" && git lfs pull >>"$LOG" 2>&1 ) || true
    # best-effort: pull submodules (real data lives in some, e.g. purplellama/CyberSOCEval_data).
    # may fail if upstream rebased away the pinned commit (e.g. caibench) — non-fatal, logged.
    [ -f "$dest/.gitmodules" ] && ( cd "$dest" && git submodule update --init --recursive --depth 1 >>"$LOG" 2>&1 ) || true
    local rsha; rsha=$(git -C "$dest" rev-parse --short HEAD 2>/dev/null || echo "?")
    local note="git"; [ -n "$sha" ] && [ "${sha#$rsha}" = "$sha" ] && note="git (upstream moved; want $sha got $rsha)"
    touch "$dest/.fetch_done"
    set_ledger "$id" DONE "$rsha" "$(dirsize "$dest")" "$note"
    log "DONE $id ($rsha, $(dirsize "$dest"))"
  else
    set_ledger "$id" FAIL "$sha" "-" "git clone failed (see log)"
    log "FAIL $id (git clone)"
  fi
}

fetch_hf(){ # id repo_id
  local id="$1" repo="$2" dest="$DATA_DIR/$1"
  if [ -z "${FORCE:-}" ] && [ -f "$dest/.fetch_done" ]; then log "SKIP $id (done)"; return 0; fi
  mkdir -p "$dest"
  log "HF   $id <- $repo (dataset)"
  if HF_HUB_DISABLE_TELEMETRY=1 python3 - "$repo" "$dest" >>"$LOG" 2>&1 <<'PY'
import sys
from huggingface_hub import snapshot_download
snapshot_download(repo_id=sys.argv[1], repo_type="dataset",
                  local_dir=sys.argv[2], local_dir_use_symlinks=False)
PY
  then
    touch "$dest/.fetch_done"
    set_ledger "$id" DONE main "$(dirsize "$dest")" "hf"
    log "DONE $id ($(dirsize "$dest"))"
  else
    set_ledger "$id" FAIL main "-" "hf download failed (gated? needs token)"
    log "FAIL $id (hf)"
  fi
}

log "=== procurement run START  data=$DATA_DIR  only='${ONLY:-ALL}' ==="
while IFS='|' read -r id category kind url sha license grading notes; do
  case "$id" in ''|\#*) continue;; esac
  [ -n "$ONLY" ] && [ "$id" != "$ONLY" ] && continue
  case "$kind" in
    git) fetch_git "$id" "$url" "$sha" ;;
    hf)  fetch_hf  "$id" "$url" ;;
    *)   log "SKIP $id (unknown kind '$kind')" ;;
  esac
done < "$CATALOG"
log "=== procurement run COMPLETE ==="
echo "----- LEDGER ($LEDGER) -----" | tee -a "$LOG" >&2
( command -v column >/dev/null && column -t -s $'\t' "$LEDGER" || cat "$LEDGER" ) | tee -a "$LOG" >&2
done_n=$(grep -cP '\tDONE\t' "$LEDGER" 2>/dev/null || echo 0)
fail_n=$(grep -cP '\tFAIL\t' "$LEDGER" 2>/dev/null || echo 0)
log "SUMMARY: DONE=$done_n FAIL=$fail_n  total_disk=$(dirsize "$DATA_DIR")"
