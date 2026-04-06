#!/usr/bin/env bash
# update_fetch_depth.sh
# Computes the maximum commits-per-day in the source repo's history,
# doubles it for a 2-day window, adds 25% headroom, then updates the
# fetch-depth value in the generate-timeslices workflow.
#
# Usage: update_fetch_depth.sh [source-repo-path]
#
# Default source-repo: ../ossf-malicious-packages

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_REPO="${1:-$(cd "$REPO_ROOT/../ossf-malicious-packages" && pwd)}"
WORKFLOW="$REPO_ROOT/.github/workflows/generate-timeslices.yml"

echo "Analyzing commit history in $SOURCE_REPO..."

MAX_PER_DAY=$(git -C "$SOURCE_REPO" log --format='%aI' \
  | cut -c1-10 \
  | sort | uniq -c | sort -rn \
  | awk 'NR==1 {print $1}')

echo "Max commits in a single day: $MAX_PER_DAY"

# 2-day window + 25% headroom, rounded up to nearest 10
FETCH_DEPTH=$(( ( (MAX_PER_DAY * 2 * 125 / 100) + 9 ) / 10 * 10 ))

echo "Setting fetch-depth to: $FETCH_DEPTH"

sed -i "s/fetch-depth: [1-9][0-9]*/fetch-depth: $FETCH_DEPTH/" "$WORKFLOW"

echo "Updated $WORKFLOW"
