#!/usr/bin/env bash
# generate_daily_timeslice.sh
# Generates a gzipped JSONL file of semantic malicious-package events for a given UTC day.
#
# Usage:
#   generate_daily_timeslice.sh [YYYY-MM-DD] [source-repo-path] [output-dir] [--staging]
#
# Defaults:
#   date        = yesterday UTC
#   source-repo = ../ossf-malicious-packages
#   output-dir  = data/timeslices  (relative to this script's parent dir)
#
# With --staging: writes to malicious-packages-staging.jsonl.gz (mutable, for today-so-far).
# Without --staging: writes to malicious-packages-YYYY-MM-DD.jsonl.gz only if it doesn't
#   exist yet (immutable finalised file for a closed day).
#
# Semantic event types emitted:
#   ingested  - new unassigned report (MAL-0000-*) appeared
#   assigned  - unassigned report renamed to a permanent ID (MAL-YYYY-NNNN)
#   updated   - existing assigned report was modified
#   withdrawn - assigned report removed from osv/malicious (moved to withdrawn/)
#
# Dependencies: git, jq, gzip (all pre-installed on GitHub Actions runners)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DATE="${1:-$(date -u -d yesterday '+%Y-%m-%d')}"
SOURCE_REPO="${2:-$(cd "$REPO_ROOT/../ossf-malicious-packages" && pwd)}"
OUTPUT_DIR="${3:-$REPO_ROOT/data/timeslices}"
STAGING="${4:-}"
SOURCE_OWNER_REPO="chromatic/ossf-malicious-packages"

SINCE="${DATE}T00:00:00Z"
UNTIL="${DATE}T23:59:59Z"

if [[ "$STAGING" == "--staging" ]]; then
  OUTPUT_FILE="$OUTPUT_DIR/malicious-packages-staging.jsonl.gz"
else
  OUTPUT_FILE="$OUTPUT_DIR/malicious-packages-${DATE}.jsonl.gz"
  # Immutable: never overwrite a finalised day.
  if [[ -f "$OUTPUT_FILE" ]]; then
    echo "Timeslice for $DATE already exists — skipping."
    exit 0
  fi
fi

echo "Generating timeslice for $DATE"
echo "  source: $SOURCE_REPO"
echo "  output: $OUTPUT_FILE"

mkdir -p "$OUTPUT_DIR"

# Collect git log output.
# Format: COMMIT <sha> <iso-timestamp> <author-email>
# Followed by a blank line, then tab-separated name-status lines.
GIT_LOG=$(git -C "$SOURCE_REPO" log \
  --name-status \
  --format='COMMIT %H %aI %ae' \
  --since="$SINCE" \
  --until="$UNTIL" \
  -- osv/malicious)

if [[ -z "$GIT_LOG" ]]; then
  echo "No commits found for $DATE — writing empty timeslice."
  printf '' | gzip -c > "$OUTPUT_FILE"
  echo "Done: $OUTPUT_FILE (empty)"
  exit 0
fi

is_unassigned() { [[ "$1" == */MAL-0000-* ]]; }
is_assigned()   { [[ "$1" == */MAL-[0-9][0-9][0-9][0-9]-[0-9]*.json ]]; }

snapshot_url() {
  local commit="$1" path="$2"
  echo "\"https://raw.githubusercontent.com/${SOURCE_OWNER_REPO}/${commit}/${path}\""
}

emit_record() {
  local record
  record=$(jq -cn "$@")
  echo "$record" | jq -ec . > /dev/null || { echo "ERROR: invalid JSON record" >&2; exit 1; }
  echo "$record"
}

RECORDS=()

# Process one commit at a time.
# We collect all raw git events for the commit first, then classify semantically.
process_commit() {
  local sha="$1" ts="$2" author="$3"
  shift 3
  local -a adds=("$@")    # interleaved: adds[0]=status adds[1]=path ...
  # Actually we receive two arrays encoded as a single list with a separator.
  # See call site below for encoding.

  # Rebuild adds/deletes/renames/modifies from the flat list passed in.
  local -a raw_adds=() raw_deletes=() raw_modifies=() raw_renames=()
  local mode=""
  for arg in "$@"; do
    case "$arg" in
      __A__)  mode=A ;;
      __M__)  mode=M ;;
      __D__)  mode=D ;;
      __R__*) mode=R; raw_renames+=("${arg#__R__}") ;;
      *)
        case "$mode" in
          A) raw_adds+=("$arg") ;;
          M) raw_modifies+=("$arg") ;;
          D) raw_deletes+=("$arg") ;;
        esac
        ;;
    esac
  done

  # Classify renames: MAL-0000-* -> MAL-YYYY-* is an assignment.
  for entry in "${raw_renames[@]+"${raw_renames[@]}"}"; do
    local old_path="${entry%%	*}"
    local new_path="${entry##*	}"
    if is_unassigned "$old_path" && is_assigned "$new_path"; then
      RECORDS+=("$(emit_record \
        --arg event      "assigned" \
        --arg timestamp  "$ts" \
        --arg commit     "$sha" \
        --arg author     "$author" \
        --arg old_path   "$old_path" \
        --arg new_path   "$new_path" \
        --argjson snapshot_url "$(snapshot_url "$sha" "$new_path")" \
        '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
          old_path: $old_path, new_path: $new_path, snapshot_url: $snapshot_url}')")
    else
      # Unexpected rename pattern — emit as raw added+deleted so nothing is lost.
      RECORDS+=("$(emit_record \
        --arg event     "ingested" \
        --arg timestamp "$ts" \
        --arg commit    "$sha" \
        --arg author    "$author" \
        --arg path      "$new_path" \
        --argjson snapshot_url "$(snapshot_url "$sha" "$new_path")" \
        '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
          path: $path, snapshot_url: $snapshot_url}')")
      RECORDS+=("$(emit_record \
        --arg event     "withdrawn" \
        --arg timestamp "$ts" \
        --arg commit    "$sha" \
        --arg author    "$author" \
        --arg path      "$old_path" \
        '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
          path: $path, snapshot_url: null}')")
    fi
  done

  # Classify adds.
  for path in "${raw_adds[@]+"${raw_adds[@]}"}"; do
    if is_unassigned "$path"; then
      RECORDS+=("$(emit_record \
        --arg event     "ingested" \
        --arg timestamp "$ts" \
        --arg commit    "$sha" \
        --arg author    "$author" \
        --arg path      "$path" \
        --argjson snapshot_url "$(snapshot_url "$sha" "$path")" \
        '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
          path: $path, snapshot_url: $snapshot_url}')")
    else
      # Assigned file added without a corresponding delete — treat as ingested directly.
      RECORDS+=("$(emit_record \
        --arg event     "ingested" \
        --arg timestamp "$ts" \
        --arg commit    "$sha" \
        --arg author    "$author" \
        --arg path      "$path" \
        --argjson snapshot_url "$(snapshot_url "$sha" "$path")" \
        '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
          path: $path, snapshot_url: $snapshot_url}')")
    fi
  done

  # Classify modifies.
  for path in "${raw_modifies[@]+"${raw_modifies[@]}"}"; do
    RECORDS+=("$(emit_record \
      --arg event     "updated" \
      --arg timestamp "$ts" \
      --arg commit    "$sha" \
      --arg author    "$author" \
      --arg path      "$path" \
      --argjson snapshot_url "$(snapshot_url "$sha" "$path")" \
      '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
        path: $path, snapshot_url: $snapshot_url}')")
  done

  # Classify deletes: bare delete with no rename partner = withdrawn.
  for path in "${raw_deletes[@]+"${raw_deletes[@]}"}"; do
    RECORDS+=("$(emit_record \
      --arg event     "withdrawn" \
      --arg timestamp "$ts" \
      --arg commit    "$sha" \
      --arg author    "$author" \
      --arg path      "$path" \
      '{event: $event, timestamp: $timestamp, commit: $commit, author: $author,
        path: $path, snapshot_url: null}')")
  done
}

# Parse git log output, grouping lines into per-commit batches.
CURRENT_SHA=""
CURRENT_TS=""
CURRENT_AUTHOR=""
CURRENT_ARGS=()

flush_commit() {
  if [[ -n "$CURRENT_SHA" ]]; then
    process_commit "$CURRENT_SHA" "$CURRENT_TS" "$CURRENT_AUTHOR" "${CURRENT_ARGS[@]+"${CURRENT_ARGS[@]}"}"
  fi
  CURRENT_ARGS=()
}

while IFS= read -r line; do
  if [[ "$line" == COMMIT\ * ]]; then
    flush_commit
    read -r _ CURRENT_SHA CURRENT_TS CURRENT_AUTHOR <<< "$line"
  elif [[ -z "$line" ]]; then
    continue
  else
    status="${line%%$'\t'*}"
    rest="${line#*$'\t'}"

    # Skip internal bookkeeping file.
    [[ "$rest" == "osv/malicious/.id-allocator" ]] && continue
    [[ "$rest" == "osv/malicious/.id-allocator"$'\t'* ]] && continue

    case "$status" in
      A)  CURRENT_ARGS+=(__A__ "$rest") ;;
      M)  CURRENT_ARGS+=(__M__ "$rest") ;;
      D)  CURRENT_ARGS+=(__D__ "$rest") ;;
      R*)
        old_path="${rest%%$'\t'*}"
        new_path="${rest##*$'\t'}"
        CURRENT_ARGS+=("__R__${old_path}	${new_path}")
        ;;
      *)  echo "WARNING: unknown status '$status' for line: $line" >&2 ;;
    esac
  fi
done <<< "$GIT_LOG"
flush_commit

echo "Found ${#RECORDS[@]} events."

# Write all records as JSONL, compressed.
# Validate every line parses as JSON before finalising.
JSONL=$(printf '%s\n' "${RECORDS[@]}")

echo "$JSONL" | jq -ec . > /dev/null || { echo "ERROR: output failed final jq validation" >&2; exit 1; }

echo "$JSONL" | gzip -c > "$OUTPUT_FILE"

echo "Done: $OUTPUT_FILE"
