#!/bin/bash
# Test all captures one at a time with cleanup between runs.
# Validates JSONL by sampling (not full-file jq), keeping disk usage bounded.

BINARY="./ct-to-timesketch"
REPORT_DIR="reports"
RESULTS_FILE="test_results.md"

echo "Building binary..."
go build -o "$BINARY" ./cmd/ct-to-timesketch/
echo ""

CAPTURES=()
while IFS= read -r line; do
  CAPTURES+=("$line")
done < <(find captures -name "*.json.gz" -type f | sort)
TOTAL=${#CAPTURES[@]}

echo "Found $TOTAL capture files to test (one at a time with cleanup)"
echo ""

{
  echo "# Full Extraction Test Results"
  echo ""
  echo "Binary: ct-to-timesketch 6.0.0 (Go, streaming, full-extraction)"
  echo "Date: $(date '+%Y-%m-%d %H:%M')"
  echo ""
  echo "| # | Hostname | GZ Size | Cache MB | Events | Artifacts | Time (s) | MB/s | JSONL | Issues |"
  echo "|---|----------|---------|----------|--------|-----------|----------|------|-------|--------|"
} > "$RESULTS_FILE"

PASS=0
FAIL=0
TOTAL_EVENTS=0
TOTAL_SECS=0

for i in "${!CAPTURES[@]}"; do
  CAP="${CAPTURES[$i]}"
  NUM=$((i + 1))
  GZ_SIZE=$(ls -lh "$CAP" | awk '{print $5}')
  ORG=$(basename "$(dirname "$CAP")")
  BASENAME=$(basename "$CAP" .json.gz)

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$NUM/$TOTAL] $ORG / $BASENAME ($GZ_SIZE)"

  # Run binary, capture all output
  START_SEC=$(date +%s)
  OUTPUT=$("$BINARY" "$CAP" 2>&1) || true
  END_SEC=$(date +%s)
  ELAPSED=$((END_SEC - START_SEC))

  # Parse key metrics from output
  HOSTNAME=$(echo "$OUTPUT" | sed -n 's/^.*Host: //p' | head -1 || true)
  HOSTNAME=${HOSTNAME:-unknown}

  EVENT_COUNT=$(echo "$OUTPUT" | grep 'TOTAL EVENTS' | awk '{print $NF}' | head -1 || true)
  EVENT_COUNT=${EVENT_COUNT:-0}

  ARTIFACT_COUNT=$(echo "$OUTPUT" | sed -n 's/.*Artifacts: \([0-9]*\).*/\1/p' | head -1 || true)
  ARTIFACT_COUNT=${ARTIFACT_COUNT:-0}

  BINARY_TIME=$(echo "$OUTPUT" | sed -n 's/.*Total time: \([0-9.]*\)s/\1/p' | head -1 || true)
  BINARY_TIME=${BINARY_TIME:-$ELAPSED}

  # Cache file size
  CACHE_FILE="${CAP%.gz}.cache"
  CACHE_MB=0
  if [ -f "$CACHE_FILE" ]; then
    CACHE_BYTES=$(stat -f%z "$CACHE_FILE" 2>/dev/null || echo 0)
    CACHE_MB=$((CACHE_BYTES / 1048576))
  fi

  # Throughput
  THROUGHPUT="-"
  if [ "$CACHE_MB" -gt 0 ] 2>/dev/null && [ "$ELAPSED" -gt 0 ] 2>/dev/null; then
    THROUGHPUT=$(echo "scale=1; $CACHE_MB / $ELAPSED" | bc 2>/dev/null || echo "-")
  fi

  # Validate JSONL output by SAMPLING (fast -- not full-file jq)
  JSONL_FILE="$REPORT_DIR/${HOSTNAME}_timeline.jsonl"
  ISSUES=""
  VALID="N/A"

  if [ -f "$JSONL_FILE" ]; then
    JSONL_LINES=$(wc -l < "$JSONL_FILE" | tr -d ' ')

    # Sample: first 500 + last 500 + 500 from middle
    MIDPOINT=$((JSONL_LINES / 2))
    SAMPLE_FILE=$(mktemp)
    head -500 "$JSONL_FILE" > "$SAMPLE_FILE"
    if [ "$JSONL_LINES" -gt 1000 ]; then
      sed -n "${MIDPOINT},$((MIDPOINT + 500))p" "$JSONL_FILE" >> "$SAMPLE_FILE"
    fi
    tail -500 "$JSONL_FILE" >> "$SAMPLE_FILE"

    # Check sampled lines are valid JSON
    BAD_JSON=$(jq -c '.' "$SAMPLE_FILE" 2>&1 | grep -c "parse error" || true)
    if [ "$BAD_JSON" -gt 0 ]; then
      ISSUES="${BAD_JSON} bad JSON in sample"
      VALID="FAIL"
    else
      VALID="OK"
    fi

    # Check required fields on sample
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
      ISSUES="$JSONL_LINES lines, clean"
      PASS=$((PASS + 1))
    elif [ "$VALID" = "WARN" ]; then
      ISSUES="$JSONL_LINES lines; $ISSUES"
      PASS=$((PASS + 1))
    else
      FAIL=$((FAIL + 1))
    fi
  else
    VALID="FAIL"
    ISSUES="no JSONL output"
    FAIL=$((FAIL + 1))
  fi

  TOTAL_EVENTS=$((TOTAL_EVENTS + EVENT_COUNT))
  TOTAL_SECS=$(echo "$TOTAL_SECS + $BINARY_TIME" | bc 2>/dev/null || echo "$TOTAL_SECS")

  echo "  Host:      $HOSTNAME"
  echo "  Events:    $EVENT_COUNT"
  echo "  Artifacts: $ARTIFACT_COUNT"
  echo "  Time:      ${BINARY_TIME}s  (${THROUGHPUT} MB/s)"
  echo "  JSONL:     $VALID  ($ISSUES)"

  echo "| $NUM | $HOSTNAME | $GZ_SIZE | $CACHE_MB | $EVENT_COUNT | $ARTIFACT_COUNT | $BINARY_TIME | $THROUGHPUT | $VALID | $ISSUES |" >> "$RESULTS_FILE"

  # --- CLEANUP: free disk before next capture ---
  echo "  Cleaning up..."
  [ -d "artifacts/${HOSTNAME}" ] && rm -rf "artifacts/${HOSTNAME}"
  [ -f "$JSONL_FILE" ] && rm -f "$JSONL_FILE"
  [ -f "$CACHE_FILE" ] && rm -f "$CACHE_FILE"
  echo ""
done

{
  echo ""
  echo "## Summary"
  echo ""
  echo "- **Captures tested**: $TOTAL"
  echo "- **Passed**: $PASS / $TOTAL"
  echo "- **Failed**: $FAIL / $TOTAL"
  echo "- **Total events generated**: $TOTAL_EVENTS"
  echo "- **Cumulative processing time**: ${TOTAL_SECS}s"
  echo ""
  echo "### Validation"
  echo ""
  echo "- JSON validity: sampled 1500 lines per file (head/mid/tail)"
  echo "- Required fields: \`datetime\`, \`timestamp_desc\`, \`message\`"
} >> "$RESULTS_FILE"

echo "============================================"
echo "  TEST COMPLETE: $PASS passed, $FAIL failed out of $TOTAL"
echo "  Total events across all captures: $TOTAL_EVENTS"
echo "  Cumulative time: ${TOTAL_SECS}s"
echo "  Full results: $RESULTS_FILE"
echo "============================================"
