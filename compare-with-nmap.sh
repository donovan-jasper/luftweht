#!/bin/bash
set -euo pipefail

echo "======================================"
echo "Host Discovery Comparison Test"
echo "======================================"
echo ""

# Configuration
TARGETS="192.168.170.0/24 192.168.171.0/24 192.168.172.0/24"
OUTPUT_DIR="./test-output/comparison-$(date +%s)"
NMAP_PORTS="22,80,443,3389,8080"

mkdir -p "$OUTPUT_DIR"

echo "[1/4] Running nmap host discovery (-Pn -p $NMAP_PORTS)..."
echo "This uses same ports as luftweht for fair comparison"
sudo nmap -Pn -p "$NMAP_PORTS" --open \
  $TARGETS \
  -oG "$OUTPUT_DIR/nmap-discovery.txt" \
  -T4 --min-rate 1000 2>&1 | grep -E "(Nmap scan|Host:)" || true

echo ""
echo "[2/4] Running luftweht discovery..."
./target/release/luftweht \
  $TARGETS \
  --mode discover-only \
  --output "$OUTPUT_DIR/luftweht" \
  -vv 2>&1 | grep -E "(INFO|Batch|Discovery complete)"

echo ""
echo "[3/4] Extracting results..."

# Extract nmap hosts
grep "Host:" "$OUTPUT_DIR/nmap-discovery.txt" | \
  grep "Ports:" | \
  awk '{print $2}' | \
  sort > "$OUTPUT_DIR/nmap-hosts.txt"

# Extract luftweht hosts
cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
  jq -r '.hosts[].ip' | \
  sort > "$OUTPUT_DIR/luftweht-hosts.txt"

echo ""
echo "[4/4] Comparison Results"
echo "======================================"
echo ""

NMAP_COUNT=$(wc -l < "$OUTPUT_DIR/nmap-hosts.txt")
LUFTWEHT_COUNT=$(wc -l < "$OUTPUT_DIR/luftweht-hosts.txt")

echo "Nmap found:      $NMAP_COUNT hosts"
echo "Luftweht found:  $LUFTWEHT_COUNT hosts"
echo ""

# Hosts found by nmap but missed by luftweht
MISSED=$(comm -23 "$OUTPUT_DIR/nmap-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | wc -l)
if [ "$MISSED" -gt 0 ]; then
    echo "❌ MISSED by luftweht: $MISSED hosts"
    comm -23 "$OUTPUT_DIR/nmap-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | while read ip; do
        echo "  - $ip"
        # Show which ports nmap found
        grep "$ip" "$OUTPUT_DIR/nmap-discovery.txt" | grep -o "Ports:.*" || true
    done
    echo ""
else
    echo "✅ No hosts missed by luftweht"
    echo ""
fi

# Hosts found by luftweht but not by nmap (false positives?)
EXTRA=$(comm -13 "$OUTPUT_DIR/nmap-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | wc -l)
if [ "$EXTRA" -gt 0 ]; then
    echo "⚠️  EXTRA in luftweht: $EXTRA hosts (not found by nmap)"
    comm -13 "$OUTPUT_DIR/nmap-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | while read ip; do
        echo "  - $ip"
    done
    echo ""
else
    echo "✅ No false positives"
    echo ""
fi

# Perfect match
if [ "$MISSED" -eq 0 ] && [ "$EXTRA" -eq 0 ]; then
    echo "🎉 PERFECT MATCH! Both tools found the same $NMAP_COUNT hosts"
fi

echo ""
echo "Full results saved to: $OUTPUT_DIR"
echo ""
echo "Files:"
echo "  - nmap-hosts.txt      : All nmap results"
echo "  - luftweht-hosts.txt  : All luftweht results"
echo "  - luftweht/scan-report.md : Detailed report"
