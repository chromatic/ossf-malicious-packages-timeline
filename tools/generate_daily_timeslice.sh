#!/usr/bin/env bash
# generate_daily_timeslice.sh
# Generates a gzipped ndjson timeslice of osv/malicious changes for a given UTC day.
#
# Usage:
#   generate_daily_timeslice.sh [YYYY-MM-DD] [source-repo-path] [output-dir] [--staging]
#
# Defaults:
#   date        = yesterday UTC
#   source-repo = ../ossf-malicious-packages
#   output-dir  = data/timeslices  (relative to this script's parent dir)
#
# With --staging: writes to timeslice-staging.json.gz (mutable, for today-so-far).
# Without --staging: writes to timeslice-YYYY-MM-DD.json.gz only if it doesn't exist yet
#   (immutable finalised file for a closed day).
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
  OUTPUT_FILE="$OUTPUT_DIR/timeslice-staging.json.gz"
else
  OUTPUT_FILE="$OUTPUT_DIR/timeslice-${DATE}.json.gz"
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

# Parse the git log and emit one JSON record per file-change event.
# Validates each record with jq before writing.
emit_record() {
  local timestamp="$1" type="$2" path="$3" commit="$4" author="$5"
  local snapshot_url

  if [[ "$type" == "deleted" ]]; then
    snapshot_url="null"
  else
    snapshot_url="\"https://raw.githubusercontent.com/${SOURCE_OWNER_REPO}/${commit}/${path}\""
  fi

  local record
  record=$(jq -cn \
    --arg timestamp "$timestamp" \
    --arg type      "$type" \
    --arg path      "$path" \
    --arg commit    "$commit" \
    --arg author    "$author" \
    --argjson snapshot_url "$snapshot_url" \
    '{timestamp: $timestamp, type: $type, path: $path, commit: $commit, author: $author, snapshot_url: $snapshot_url}')

  # Validate the record is well-formed JSON before accepting it.
  echo "$record" | jq -ec . > /dev/null || { echo "ERROR: invalid JSON record for $path at $commit" >&2; exit 1; }

  echo "$record"
}

# Parse git log output line by line.
# State: current commit fields, accumulate records.
CURRENT_SHA=""
CURRENT_TS=""
CURRENT_AUTHOR=""
RECORDS=()

while IFS= read -r line; do
  if [[ "$line" == COMMIT\ * ]]; then
    # Parse: COMMIT <sha> <timestamp> <author>
    read -r _ sha ts author <<< "$line"
    CURRENT_SHA="$sha"
    CURRENT_TS="$ts"
    CURRENT_AUTHOR="$author"
  elif [[ -z "$line" ]]; then
    # Blank line — separator between header and file list, or between commits.
    continue
  else
    # File status line — tab-separated.
    status="${line%%$'\t'*}"
    rest="${line#*$'\t'}"

    # Skip the internal bookkeeping file.
    [[ "$rest" == "osv/malicious/.id-allocator" ]] && continue
    [[ "$rest" == "osv/malicious/.id-allocator"$'\t'* ]] && continue

    case "$status" in
      A)
        RECORDS+=("$(emit_record "$CURRENT_TS" "added"    "$rest"                  "$CURRENT_SHA" "$CURRENT_AUTHOR")")
        ;;
      M)
        RECORDS+=("$(emit_record "$CURRENT_TS" "modified" "$rest"                  "$CURRENT_SHA" "$CURRENT_AUTHOR")")
        ;;
      D)
        RECORDS+=("$(emit_record "$CURRENT_TS" "deleted"  "$rest"                  "$CURRENT_SHA" "$CURRENT_AUTHOR")")
        ;;
      R*)
        # Rename: <old-path>\t<new-path>
        old_path="${rest%%$'\t'*}"
        new_path="${rest##*$'\t'}"
        RECORDS+=("$(emit_record "$CURRENT_TS" "deleted"  "$old_path"              "$CURRENT_SHA" "$CURRENT_AUTHOR")")
        RECORDS+=("$(emit_record "$CURRENT_TS" "added"    "$new_path"              "$CURRENT_SHA" "$CURRENT_AUTHOR")")
        ;;
      *)
        echo "WARNING: unknown status '$status' for line: $line" >&2
        ;;
    esac
  fi
done <<< "$GIT_LOG"

echo "Found ${#RECORDS[@]} file-change events."

# Write all records as ndjson, compressed.
# Validate the complete output can be re-parsed by jq before finalising.
NDJSON=$(printf '%s\n' "${RECORDS[@]}")

echo "$NDJSON" | jq -ec . > /dev/null || { echo "ERROR: output failed final jq validation" >&2; exit 1; }

echo "$NDJSON" | gzip -c > "$OUTPUT_FILE"

echo "Done: $OUTPUT_FILE"
