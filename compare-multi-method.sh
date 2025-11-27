#!/bin/bash
set -euo pipefail

echo "======================================================================"
echo "Multi-Method Discovery Comparison Test (REQUIRES SUDO)"
echo "======================================================================"
echo ""

# Configuration
TARGETS="192.168.170.0/24 192.168.171.0/24 192.168.172.0/24"
OUTPUT_DIR="./test-output/multi-method-comparison-$(date +%s)"
DISCOVERY_PORTS="22,80,443,3389,8080"

mkdir -p "$OUTPUT_DIR"

echo "[1/4] Running nmap TCP discovery (-Pn -p $DISCOVERY_PORTS)..."
echo "This scans the same ports as luftweht for fair comparison"
sudo nmap -Pn -p "$DISCOVERY_PORTS" --open \
  $TARGETS \
  -oG "$OUTPUT_DIR/nmap-tcp.txt" \
  -T4 --min-rate 1000 2>&1 | grep -E "(Nmap scan|Host:)" || true

echo ""
echo "[2/4] Running nmap with -PE (ICMP ping) + TCP..."
sudo nmap -PE -Pn -p "$DISCOVERY_PORTS" --open \
  $TARGETS \
  -oG "$OUTPUT_DIR/nmap-icmp-tcp.txt" \
  -T4 --min-rate 1000 2>&1 | grep -E "(Nmap scan|Host:)" || true

echo ""
echo "[3/4] Running luftweht multi-method discovery (TCP+ICMP+ARP+SYN)..."
sudo ./target/release/luftweht \
  $TARGETS \
  --mode discover-only \
  --output "$OUTPUT_DIR/luftweht" \
  -vv 2>&1 | grep -E "(INFO|WARN|Batch|Discovery|hosts found)"

echo ""
echo "[4/4] Extracting and comparing results..."

# Extract nmap TCP-only hosts
grep "Host:" "$OUTPUT_DIR/nmap-tcp.txt" | \
  grep "Ports:" | \
  awk '{print $2}' | \
  sort -u > "$OUTPUT_DIR/nmap-tcp-hosts.txt"

# Extract nmap ICMP+TCP hosts
grep "Host:" "$OUTPUT_DIR/nmap-icmp-tcp.txt" | \
  grep "Ports:" | \
  awk '{print $2}' | \
  sort -u > "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt"

# Extract luftweht hosts
cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
  jq -r '.hosts[].ip' | \
  sort -u > "$OUTPUT_DIR/luftweht-hosts.txt"

echo ""
echo "======================================================================"
echo "COMPARISON RESULTS"
echo "======================================================================"
echo ""

NMAP_TCP_COUNT=$(wc -l < "$OUTPUT_DIR/nmap-tcp-hosts.txt" | tr -d ' ')
NMAP_ICMP_COUNT=$(wc -l < "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" | tr -d ' ')
LUFTWEHT_COUNT=$(wc -l < "$OUTPUT_DIR/luftweht-hosts.txt" | tr -d ' ')

echo "Method Comparison:"
echo "  Nmap (TCP only):           $NMAP_TCP_COUNT hosts"
echo "  Nmap (ICMP+TCP):           $NMAP_ICMP_COUNT hosts"
echo "  Luftweht (TCP+ICMP+ARP+SYN): $LUFTWEHT_COUNT hosts"
echo ""

# Hosts found by nmap ICMP+TCP but missed by luftweht
MISSED=$(comm -23 "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | wc -l | tr -d ' ')
if [ "$MISSED" -gt 0 ]; then
    echo "❌ MISSED by luftweht: $MISSED hosts"
    comm -23 "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | while read ip; do
        echo "  - $ip"
        # Show which ports nmap found
        grep "$ip" "$OUTPUT_DIR/nmap-icmp-tcp.txt" | grep -o "Ports:.*" || true
    done
    echo ""
else
    echo "✅ No hosts missed by luftweht"
    echo ""
fi

# Hosts found by luftweht but not by nmap
EXTRA=$(comm -13 "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | wc -l | tr -d ' ')
if [ "$EXTRA" -gt 0 ]; then
    echo "🎯 EXTRA hosts found by luftweht: $EXTRA hosts"
    echo "(These may be found by ARP or TCP SYN that nmap's ICMP+TCP missed)"
    comm -13 "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" "$OUTPUT_DIR/luftweht-hosts.txt" | while read ip; do
        echo "  - $ip"
        # Show which ports/methods luftweht found
        cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
          jq -r ".hosts[] | select(.ip == \"$ip\") | \"    Methods: \(.discovery_methods | join(\", \"))  Ports: \(.ports | keys | join(\", \"))\"" 2>/dev/null || true
    done
    echo ""
else
    echo "✅ No additional hosts beyond nmap"
    echo ""
fi

# Perfect match
if [ "$MISSED" -eq 0 ] && [ "$EXTRA" -eq 0 ]; then
    echo "🎉 PERFECT MATCH! Both tools found the same $LUFTWEHT_COUNT hosts"
fi

# Show ICMP benefit
ICMP_BENEFIT=$(comm -13 "$OUTPUT_DIR/nmap-tcp-hosts.txt" "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" | wc -l | tr -d ' ')
if [ "$ICMP_BENEFIT" -gt 0 ]; then
    echo ""
    echo "📊 ICMP Discovery Benefit:"
    echo "  Nmap found $ICMP_BENEFIT additional hosts using ICMP that TCP alone missed"
    comm -13 "$OUTPUT_DIR/nmap-tcp-hosts.txt" "$OUTPUT_DIR/nmap-icmp-tcp-hosts.txt" | while read ip; do
        echo "    - $ip"
    done
fi

echo ""
echo "======================================================================"
echo "DISCOVERY METHOD BREAKDOWN (from luftweht)"
echo "======================================================================"

# Parse luftweht scan report for method details
if [ -f "$OUTPUT_DIR/luftweht/scan-report.md" ]; then
    echo ""
    echo "Check the full report for discovery method details:"
    echo "  $OUTPUT_DIR/luftweht/scan-report.md"
    echo ""

    # Try to extract discovery method stats from JSON
    echo "Hosts discovered by each method:"
    for method in "RustscanCustom" "IcmpEcho" "Arp" "TcpSyn"; do
        count=$(cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
          jq -r ".hosts[] | select(.discovery_methods[] | contains(\"$method\")) | .ip" 2>/dev/null | \
          wc -l | tr -d ' ')
        if [ "$count" -gt 0 ]; then
            echo "  $method: $count hosts"
        fi
    done
fi

echo ""
echo "Full results saved to: $OUTPUT_DIR"
echo ""
echo "Files:"
echo "  - nmap-tcp-hosts.txt         : Nmap TCP-only results"
echo "  - nmap-icmp-tcp-hosts.txt    : Nmap ICMP+TCP results"
echo "  - luftweht-hosts.txt         : Luftweht multi-method results"
echo "  - luftweht/scan-report.md    : Detailed luftweht report"
echo "  - luftweht/scan-results.json : Full JSON output with methods"
echo ""
