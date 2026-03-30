#!/bin/bash
# CloudRules Battery Test -- runs all captures with --cloudrules, validates JSONL,
# generates per-capture forensic assessments, and writes a single markdown report.
# Cleans up cache/artifacts/JSONL after each capture to maintain healthy disk space.

BINARY="./ct-to-timesketch"
REPORT_DIR="reports"
RESULTS_FILE="battery_test_results.md"
CR_PATH="cloudrules/CloudRules_rv3160001.json.gz"
MIN_DISK_GB=20

get_disk_free_gb() {
  df -g . 2>/dev/null | tail -1 | awk '{print $4}' || df -h . | tail -1 | awk '{gsub(/[^0-9]/,"",$4); print $4}'
}

get_disk_free_human() {
  df -h . | tail -1 | awk '{print $4}'
}

echo "=========================================="
echo "  CloudRules Battery Test"
echo "=========================================="
echo ""

STARTING_DISK=$(get_disk_free_human)
echo "Disk free: $STARTING_DISK"

echo "Building binary..."
go build -o "$BINARY" ./cmd/ct-to-timesketch/
VERSION=$("$BINARY" --version 2>&1 | head -1)
echo "Binary: $VERSION"
echo ""

if [ ! -f "$CR_PATH" ]; then
  echo "ERROR: CloudRules file not found at $CR_PATH"
  exit 1
fi

CAPTURES=()
while IFS= read -r line; do
  CAPTURES+=("$line")
done < <(find captures -name "*.json.gz" -type f | sort)
TOTAL=${#CAPTURES[@]}

echo "Found $TOTAL capture files to test"
echo "CloudRules: $CR_PATH"
echo ""

# Initialize report
{
  echo "# CloudRules Battery Test Results"
  echo ""
  echo "**Binary**: $VERSION"
  echo "**Date**: $(date '+%Y-%m-%d %H:%M')"
  echo "**CloudRules**: $(basename "$CR_PATH")"
  echo "**Starting disk**: $STARTING_DISK free"
  echo ""
  echo "## Summary Table"
  echo ""
  echo "| # | Organization | Hostname | GZ Size | Events | CR Detections | CR Events | Top Score | Time | JSONL |"
  echo "|---|-------------|----------|---------|--------|---------------|-----------|-----------|------|-------|"
} > "$RESULTS_FILE"

# Temp file to accumulate per-capture assessments
ASSESS_FILE=$(mktemp)

PASS=0
FAIL=0
TOTAL_EVENTS=0
TOTAL_CR_DETECTIONS=0
TOTAL_CR_EVENTS=0
TOTAL_SECS=0
MIN_DISK="$STARTING_DISK"

for i in "${!CAPTURES[@]}"; do
  CAP="${CAPTURES[$i]}"
  NUM=$((i + 1))
  GZ_SIZE=$(ls -lh "$CAP" | awk '{print $5}')
  ORG=$(basename "$(dirname "$CAP")")
  BASENAME=$(basename "$CAP" .json.gz)

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$NUM/$TOTAL] $ORG / $BASENAME ($GZ_SIZE)"

  # Run binary with CloudRules
  START_SEC=$(date +%s)
  OUTPUT=$("$BINARY" "$CAP" --cloudrules --cloudrules-path "$CR_PATH" 2>&1) || true
  END_SEC=$(date +%s)
  ELAPSED=$((END_SEC - START_SEC))

  # --- Parse standard metrics ---
  HOSTNAME=$(echo "$OUTPUT" | sed -n 's/^.*Host: //p' | head -1 || true)
  HOSTNAME=${HOSTNAME:-unknown}

  EVENT_COUNT=$(echo "$OUTPUT" | grep 'TOTAL EVENTS' | awk '{print $NF}' | head -1 || true)
  EVENT_COUNT=${EVENT_COUNT:-0}

  ARTIFACT_COUNT=$(echo "$OUTPUT" | sed -n 's/.*Artifacts: \([0-9]*\).*/\1/p' | head -1 || true)
  ARTIFACT_COUNT=${ARTIFACT_COUNT:-0}

  BINARY_TIME=$(echo "$OUTPUT" | sed -n 's/.*Total time: \([0-9.]*\)s/\1/p' | head -1 || true)
  BINARY_TIME=${BINARY_TIME:-$ELAPSED}

  # Format time as Xm Ys for readability
  ELAPSED_MIN=$((ELAPSED / 60))
  ELAPSED_REM=$((ELAPSED % 60))
  if [ "$ELAPSED_MIN" -gt 0 ]; then
    TIME_FMT="${ELAPSED_MIN}m${ELAPSED_REM}s"
  else
    TIME_FMT="${ELAPSED}s"
  fi

  # Cache file size
  CACHE_FILE="${CAP%.gz}.cache"
  CACHE_MB=0
  if [ -f "$CACHE_FILE" ]; then
    CACHE_BYTES=$(stat -f%z "$CACHE_FILE" 2>/dev/null || stat -c%s "$CACHE_FILE" 2>/dev/null || echo 0)
    CACHE_MB=$((CACHE_BYTES / 1048576))
  fi

  # --- Parse CloudRules metrics ---
  CR_DETECTIONS=$(echo "$OUTPUT" | grep 'CloudRules:' | grep 'detections across' | awk '{print $2}' | head -1 || true)
  CR_DETECTIONS=${CR_DETECTIONS:-0}

  CR_EVENTS=$(echo "$OUTPUT" | grep 'Tagged.*CloudRules' | awk '{print $2}' | head -1 || true)
  CR_EVENTS=${CR_EVENTS:-0}

  CR_NOTABLE=$(echo "$OUTPUT" | grep 'NOTABLE' | grep -v 'LIKELY' | awk '{print $NF}' | head -1 || true)
  CR_NOTABLE=${CR_NOTABLE:-0}

  CR_LIKELY=$(echo "$OUTPUT" | grep 'LIKELY_NOTABLE' | awk '{print $NF}' | head -1 || true)
  CR_LIKELY=${CR_LIKELY:-0}

  CR_UNKNOWN=$(echo "$OUTPUT" | grep '    UNKNOWN' | awk '{print $NF}' | head -1 || true)
  CR_UNKNOWN=${CR_UNKNOWN:-0}

  # Top detection types (up to 3)
  CR_TOP_TYPES=$(echo "$OUTPUT" | grep -A5 'Top detection types:' | grep '^ ' | head -3 | awk '{printf "%s(%s) ", $1, $NF}' || true)
  CR_TOP_TYPES=${CR_TOP_TYPES:-none}

  # Determine top score
  TOP_SCORE="none"
  if [ "$CR_NOTABLE" != "0" ] && [ -n "$CR_NOTABLE" ]; then
    TOP_SCORE="NOTABLE"
  elif [ "$CR_LIKELY" != "0" ] && [ -n "$CR_LIKELY" ]; then
    TOP_SCORE="LIKELY_NOTABLE"
  elif [ "$CR_UNKNOWN" != "0" ] && [ -n "$CR_UNKNOWN" ]; then
    TOP_SCORE="UNKNOWN"
  fi

  # --- Validate JSONL ---
  JSONL_FILE="$REPORT_DIR/${HOSTNAME}_timeline.jsonl"
  ISSUES=""
  VALID="N/A"

  if [ -f "$JSONL_FILE" ]; then
    JSONL_LINES=$(wc -l < "$JSONL_FILE" | tr -d ' ')

    MIDPOINT=$((JSONL_LINES / 2))
    SAMPLE_FILE=$(mktemp)
    head -500 "$JSONL_FILE" > "$SAMPLE_FILE"
    if [ "$JSONL_LINES" -gt 1000 ]; then
      sed -n "${MIDPOINT},$((MIDPOINT + 500))p" "$JSONL_FILE" >> "$SAMPLE_FILE"
    fi
    tail -500 "$JSONL_FILE" >> "$SAMPLE_FILE"

    BAD_JSON=$(jq -c '.' "$SAMPLE_FILE" 2>&1 | grep -c "parse error" || true)
    if [ "$BAD_JSON" -gt 0 ]; then
      ISSUES="${BAD_JSON} bad JSON in sample"
      VALID="FAIL"
    else
      VALID="OK"
    fi

    MISSING=$(jq -r '
      if (.datetime == null or .datetime == "") then "no_datetime"
      elif (.timestamp_desc == null or .timestamp_desc == "") then "no_ts_desc"
      elif (.message == null or .message == "") then "no_message"
      else empty end
    ' "$SAMPLE_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -3 || true)

    rm -f "$SAMPLE_FILE"

    if [ -n "$MISSING" ]; then
      FIELD_SUMMARY=$(echo "$MISSING" | awk '{printf "%s(%s) ", $2, $1}')
      if [ -z "$ISSUES" ]; then ISSUES="$FIELD_SUMMARY"; else ISSUES="$ISSUES; $FIELD_SUMMARY"; fi
      if [ "$VALID" = "OK" ]; then VALID="WARN"; fi
    fi

    if [ "$VALID" = "OK" ] && [ -z "$ISSUES" ]; then
      ISSUES="clean"
      PASS=$((PASS + 1))
    elif [ "$VALID" = "WARN" ]; then
      PASS=$((PASS + 1))
    else
      FAIL=$((FAIL + 1))
    fi
  else
    VALID="FAIL"
    ISSUES="no JSONL output"
    FAIL=$((FAIL + 1))
  fi

  # --- Accumulate totals ---
  TOTAL_EVENTS=$((TOTAL_EVENTS + EVENT_COUNT))
  TOTAL_CR_DETECTIONS=$((TOTAL_CR_DETECTIONS + CR_DETECTIONS))
  TOTAL_CR_EVENTS=$((TOTAL_CR_EVENTS + CR_EVENTS))
  TOTAL_SECS=$(echo "$TOTAL_SECS + $BINARY_TIME" | bc 2>/dev/null || echo "$TOTAL_SECS")

  # --- Console output ---
  echo "  Host:        $HOSTNAME"
  echo "  Events:      $EVENT_COUNT"
  echo "  CloudRules:  $CR_DETECTIONS detections / $CR_EVENTS events tagged ($TOP_SCORE)"
  echo "  Top types:   $CR_TOP_TYPES"
  echo "  Time:        $TIME_FMT"
  echo "  JSONL:       $VALID ($ISSUES)"

  # --- Write summary table row ---
  echo "| $NUM | $ORG | $HOSTNAME | $GZ_SIZE | $EVENT_COUNT | $CR_DETECTIONS | $CR_EVENTS | $TOP_SCORE | $TIME_FMT | $VALID |" >> "$RESULTS_FILE"

  # --- Generate per-capture assessment paragraph ---
  ASSESSMENT="**${ORG} / ${HOSTNAME}** -- "
  ASSESSMENT+="Processed ${GZ_SIZE} capture producing $(printf "%'d" "$EVENT_COUNT") timeline events in ${TIME_FMT}. "

  if [ "$CR_DETECTIONS" -gt 0 ] 2>/dev/null; then
    ASSESSMENT+="CloudRules identified ${CR_DETECTIONS} detections across ${CR_EVENTS} events"
    if [ "$CR_NOTABLE" != "0" ] && [ -n "$CR_NOTABLE" ]; then
      ASSESSMENT+=" (${CR_NOTABLE} NOTABLE"
      if [ "$CR_LIKELY" != "0" ] && [ -n "$CR_LIKELY" ]; then
        ASSESSMENT+=", ${CR_LIKELY} LIKELY_NOTABLE"
      fi
      ASSESSMENT+=")"
    fi
    ASSESSMENT+=". Top findings: ${CR_TOP_TYPES}. "

    # Forensic interpretation based on detection types
    if echo "$CR_TOP_TYPES" | grep -qi "REMOTE_ACCESS"; then
      ASSESSMENT+="Remote management software detected -- verify whether authorized for this endpoint. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "POWERSHELL"; then
      ASSESSMENT+="PowerShell-based activity flagged -- review command lines for download cradles or encoded commands. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "DATA_TRANSFER"; then
      ASSESSMENT+="Data transfer tools present -- assess for potential exfiltration activity. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "DEFENDER"; then
      ASSESSMENT+="Windows Defender configuration changes detected -- check for intentional security weakening. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "DOUBLE_FILE"; then
      ASSESSMENT+="Double file extensions detected -- possible masquerading of malicious executables. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "DLL_INJECTION"; then
      ASSESSMENT+="DLL injection indicators found -- investigate memory-resident threats. "
    fi
    if echo "$CR_TOP_TYPES" | grep -qi "DOMAIN\|EXTERNAL_STORAGE"; then
      ASSESSMENT+="Suspicious domain activity observed -- review for C2 or exfiltration staging. "
    fi
  else
    ASSESSMENT+="CloudRules found no detections. "
  fi

  ASSESSMENT+="JSONL validation: ${VALID}."

  {
    echo ""
    echo "### ${NUM}. ${ORG} / ${HOSTNAME}"
    echo ""
    echo "> ${ASSESSMENT}"
  } >> "$ASSESS_FILE"

  # --- CLEANUP: free disk before next capture ---
  echo "  Cleaning up..."
  [ -f "$CACHE_FILE" ] && rm -f "$CACHE_FILE"
  [ -d "artifacts/${HOSTNAME}" ] && rm -rf "artifacts/${HOSTNAME}"
  [ -f "$JSONL_FILE" ] && rm -f "$JSONL_FILE"

  # Safety sweep for stray .cache files from any failed runs
  find captures -name "*.cache" -type f -delete 2>/dev/null || true

  # Remove empty parent dirs
  rmdir artifacts 2>/dev/null || true
  rmdir reports 2>/dev/null || true

  DISK_FREE=$(get_disk_free_human)
  echo "  Disk free: $DISK_FREE"

  # Track minimum disk
  DISK_GB=$(get_disk_free_gb)
  MIN_GB=$(echo "$MIN_DISK" | grep -o '[0-9]*' | head -1 || echo 999)
  if [ "$DISK_GB" -lt "$MIN_GB" ] 2>/dev/null; then
    MIN_DISK="$DISK_FREE"
  fi

  # Warn if disk is getting low
  if [ "$DISK_GB" -lt "$MIN_DISK_GB" ] 2>/dev/null; then
    echo "  WARNING: Disk space below ${MIN_DISK_GB}GB threshold!"
    echo "  Aborting to protect disk health."
    echo "" >> "$RESULTS_FILE"
    echo "**ABORTED**: Disk space fell below ${MIN_DISK_GB}GB after capture $NUM." >> "$RESULTS_FILE"
    break
  fi

  echo ""
done

# --- Write assessments section ---
{
  echo ""
  echo "## Per-Capture Assessments"
  cat "$ASSESS_FILE"
} >> "$RESULTS_FILE"
rm -f "$ASSESS_FILE"

# --- Write aggregate summary ---
ENDING_DISK=$(get_disk_free_human)
TOTAL_MIN=$(echo "$TOTAL_SECS / 60" | bc 2>/dev/null || echo "?")

{
  echo ""
  echo "## Aggregate Summary"
  echo ""
  echo "- **Captures tested**: $TOTAL"
  echo "- **Passed**: $PASS / $TOTAL"
  echo "- **Failed**: $FAIL / $TOTAL"
  echo "- **Total events**: $(printf "%'d" "$TOTAL_EVENTS")"
  echo "- **Total CloudRules detections**: $(printf "%'d" "$TOTAL_CR_DETECTIONS")"
  echo "- **Total events tagged**: $(printf "%'d" "$TOTAL_CR_EVENTS")"
  echo "- **Cumulative processing time**: ${TOTAL_SECS}s (~${TOTAL_MIN} min)"
  echo ""
  echo "### Disk Usage"
  echo ""
  echo "- Starting free: $STARTING_DISK"
  echo "- Minimum free during sweep: $MIN_DISK"
  echo "- Ending free: $ENDING_DISK"
  echo ""
  echo "### Validation Method"
  echo ""
  echo "- JSON validity: sampled 1,500 lines per file (head 500 / mid 500 / tail 500)"
  echo "- Required fields checked: \`datetime\`, \`timestamp_desc\`, \`message\`"
  echo "- Cleanup: cache, artifacts, and JSONL removed after each capture"
} >> "$RESULTS_FILE"

echo "============================================"
echo "  BATTERY TEST COMPLETE"
echo "  $PASS passed, $FAIL failed out of $TOTAL"
echo "  Total events: $(printf "%'d" "$TOTAL_EVENTS")"
echo "  Total CloudRules detections: $(printf "%'d" "$TOTAL_CR_DETECTIONS")"
echo "  Cumulative time: ${TOTAL_SECS}s"
echo "  Disk: $STARTING_DISK -> $ENDING_DISK"
echo "  Full report: $RESULTS_FILE"
echo "============================================"
