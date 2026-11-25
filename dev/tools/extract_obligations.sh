#!/bin/bash
# Extract normative obligations from RFC 9171 sections 4-7

RFC_FILE="spec/sources/rfc9171.txt"
OUTPUT_FILE="spec/obligations_raw.txt"

echo "Extracting normative statements from RFC 9171 §§4-7..." > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract lines 578-2042 (sections 4-7) and find normative statements
sed -n '578,2042p' "$RFC_FILE" | grep -n -B2 -A2 -E " (MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED|SHOULD NOT|SHOULD|MAY) " >> "$OUTPUT_FILE"

echo ""
echo "Extracted $(grep -c -E ' (MUST|SHALL|REQUIRED|SHOULD|MAY) ' "$OUTPUT_FILE") normative statements"
echo "Output written to $OUTPUT_FILE"
