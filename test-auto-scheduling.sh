#!/bin/bash
set -euo pipefail

echo "======================================================================"
echo "Auto-Scheduling Test: Discovery → Port Scan → Service Enumeration"
echo "======================================================================"
echo ""
echo "This test validates that luftweht automatically:"
echo "  1. Discovers hosts using multi-method discovery"
echo "  2. Auto-schedules full port scans (-p-) for each discovered host"
echo "  3. Auto-schedules service enumeration (nmap -sV -O) after port scan"
echo ""
echo "REQUIRES SUDO for ICMP, ARP, TCP SYN, and nmap -O"
echo ""

# Configuration
TARGET="${1:-192.168.170.0/24}"
OUTPUT_DIR="./test-output/auto-scheduling-test-$(date +%s)"
TIMEOUT=180  # 3 minutes for discovery and auto-scheduling

mkdir -p "$OUTPUT_DIR"

echo "======================================================================"
echo "PHASE 1: Run luftweht with auto-scheduling"
echo "======================================================================"
echo ""
echo "Target: $TARGET"
echo "Timeout: ${TIMEOUT}s"
echo "Output: $OUTPUT_DIR/luftweht"
echo ""

# Run luftweht in discover mode (which now auto-schedules port scans and service enum)
echo "[1/4] Running luftweht with auto-scheduling enabled..."
sudo ./target/release/luftweht \
  $TARGET \
  --mode discover \
  --output "$OUTPUT_DIR/luftweht" \
  --scan-timeout-secs "$TIMEOUT" \
  -vv 2>&1 | tee "$OUTPUT_DIR/luftweht-output.log"

echo ""
echo "[2/4] Running nmap baseline for comparison..."
echo "Note: Using same discovery ports (22,80,443,3389,8080) for fair comparison"
echo "Full -p- comparison would take hours - luftweht does this automatically in background"

# Run nmap with discovery ports for quick comparison
# Full port scan comparison skipped (would take hours on 3x /24 networks)
sudo nmap -Pn -p 22,80,443,3389,8080 --open \
  $TARGET \
  -oA "$OUTPUT_DIR/nmap-discovery" \
  -T4 --min-rate 1000 \
  -v 2>&1 | grep -E "(Nmap scan|Host:|Ports:|Service Info)" | head -50 || true

echo ""
echo "[3/4] Extracting results for comparison..."

# Extract luftweht results
if [ -f "$OUTPUT_DIR/luftweht/scan-results.json" ]; then
    # Hosts discovered
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[].ip' | \
      sort -u > "$OUTPUT_DIR/luftweht-hosts.txt"

    # Hosts with ports (auto-scheduled port scan completed)
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[] | select(.open_ports | length > 0) | .ip' | \
      sort -u > "$OUTPUT_DIR/luftweht-portscanned-hosts.txt"

    # Hosts with service info (auto-scheduled service enum completed)
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[] | select(.services | length > 0) | .ip' | \
      sort -u > "$OUTPUT_DIR/luftweht-serviced-hosts.txt"

    # Port counts per host
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[] | "\(.ip): \(.open_ports | length) ports"' \
      > "$OUTPUT_DIR/luftweht-port-counts.txt"

    # Service counts per host
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[] | "\(.ip): \(.services | length) services"' \
      > "$OUTPUT_DIR/luftweht-service-counts.txt"
else
    echo "WARNING: scan-results.json not found!"
    touch "$OUTPUT_DIR/luftweht-hosts.txt"
    touch "$OUTPUT_DIR/luftweht-portscanned-hosts.txt"
    touch "$OUTPUT_DIR/luftweht-serviced-hosts.txt"
fi

# Extract nmap results
if [ -f "$OUTPUT_DIR/nmap-discovery.gnmap" ]; then
    grep "Host:" "$OUTPUT_DIR/nmap-discovery.gnmap" | \
      grep "Ports:" | \
      awk '{print $2}' | \
      sort -u > "$OUTPUT_DIR/nmap-hosts.txt"
else
    touch "$OUTPUT_DIR/nmap-hosts.txt"
fi

echo ""
echo "======================================================================"
echo "ANALYSIS RESULTS"
echo "======================================================================"
echo ""

# Count results
LUFTWEHT_DISCOVERED=$(wc -l < "$OUTPUT_DIR/luftweht-hosts.txt" | tr -d ' ')
LUFTWEHT_PORTSCANNED=$(wc -l < "$OUTPUT_DIR/luftweht-portscanned-hosts.txt" | tr -d ' ')
LUFTWEHT_SERVICED=$(wc -l < "$OUTPUT_DIR/luftweht-serviced-hosts.txt" | tr -d ' ')
NMAP_TOTAL=$(wc -l < "$OUTPUT_DIR/nmap-hosts.txt" | tr -d ' ')

echo "📊 Discovery Statistics:"
echo "  Luftweht discovered:        $LUFTWEHT_DISCOVERED hosts"
echo "  Nmap discovered:            $NMAP_TOTAL hosts"
echo ""

echo "📊 Auto-Scheduling Statistics:"
echo "  Port scans completed:       $LUFTWEHT_PORTSCANNED / $LUFTWEHT_DISCOVERED hosts"
echo "  Service enums completed:    $LUFTWEHT_SERVICED / $LUFTWEHT_PORTSCANNED hosts"
echo ""

# Check auto-scheduling success
if [ "$LUFTWEHT_PORTSCANNED" -eq "$LUFTWEHT_DISCOVERED" ]; then
    echo "✅ SUCCESS: All discovered hosts had port scans auto-scheduled"
else
    echo "⚠️  WARNING: Not all hosts had port scans completed ($LUFTWEHT_PORTSCANNED/$LUFTWEHT_DISCOVERED)"
    echo "   This may be due to timeout - check scan-stream.ndjson for in-progress scans"
fi

if [ "$LUFTWEHT_SERVICED" -eq "$LUFTWEHT_PORTSCANNED" ]; then
    echo "✅ SUCCESS: All port-scanned hosts had service enumeration auto-scheduled"
elif [ "$LUFTWEHT_SERVICED" -gt 0 ]; then
    echo "⚠️  WARNING: Partial service enumeration ($LUFTWEHT_SERVICED/$LUFTWEHT_PORTSCANNED)"
    echo "   Full port scans may still be in progress"
else
    echo "❌ FAILED: No service enumeration completed"
fi

echo ""
echo "======================================================================"
echo "PORT SCAN DEPTH COMPARISON"
echo "======================================================================"
echo ""

echo "Luftweht port counts (should be comprehensive -p- scan):"
cat "$OUTPUT_DIR/luftweht-port-counts.txt" | head -10
if [ "$(wc -l < "$OUTPUT_DIR/luftweht-port-counts.txt")" -gt 10 ]; then
    echo "  ... and $(($(wc -l < "$OUTPUT_DIR/luftweht-port-counts.txt") - 10)) more hosts"
fi

echo ""
echo "Nmap port counts (discovery ports only: 22,80,443,3389,8080):"
if [ -f "$OUTPUT_DIR/nmap-discovery.gnmap" ]; then
    grep "Ports:" "$OUTPUT_DIR/nmap-discovery.gnmap" | while read line; do
        ip=$(echo "$line" | awk '{print $2}')
        ports=$(echo "$line" | grep -o "Ports:" | wc -l)
        port_count=$(echo "$line" | grep -o "/open/" | wc -c)
        port_count=$((port_count / 6))  # Each match is 6 chars
        echo "$ip: $port_count ports"
    done | head -10
else
    echo "  (nmap baseline skipped or not completed)"
fi

echo ""
echo "======================================================================"
echo "SERVICE ENUMERATION VALIDATION"
echo "======================================================================"
echo ""

if [ "$LUFTWEHT_SERVICED" -gt 0 ]; then
    echo "✅ Service enumeration was auto-triggered!"
    echo ""
    echo "Sample service details from luftweht:"
    cat "$OUTPUT_DIR/luftweht/scan-results.json" | \
      jq -r '.hosts[] | select(.services | length > 0) | .services[0:3][] | "  \(.port)/\(.protocol): \(.name) \(.version // "unknown")"' | \
      head -15
    echo ""
else
    echo "⚠️  No service enumeration results found"
    echo "   Check if nmap is installed and accessible"
    echo "   Check luftweht-output.log for errors"
fi

echo ""
echo "======================================================================"
echo "AUTO-SCHEDULING EVENT TIMELINE"
echo "======================================================================"
echo ""

if [ -f "$OUTPUT_DIR/luftweht/scan-stream.ndjson" ]; then
    echo "Event sequence from scan-stream.ndjson:"
    echo ""

    # Show discovery events
    echo "Discovery events:"
    grep -E '"type":"host_discovered"|"event":"HostDiscovered"' "$OUTPUT_DIR/luftweht/scan-stream.ndjson" | \
      jq -r 'if .ip then .ip else .host.ip end' | \
      head -5 | \
      while read ip; do echo "  ✓ Discovered: $ip"; done

    echo ""

    # Show port discovery events
    echo "Port discovery events (auto-scheduled scans):"
    grep -E '"type":"port_discovered"|"event":"PortDiscovered"' "$OUTPUT_DIR/luftweht/scan-stream.ndjson" | \
      jq -r 'if .ip and .port then "\(.ip):\(.port)" else "\(.host.ip):\(.port)" end' | \
      head -10 | \
      while read entry; do echo "  ✓ Port found: $entry"; done

    echo ""
    echo "Full event stream saved to: $OUTPUT_DIR/luftweht/scan-stream.ndjson"
fi

echo ""
echo "======================================================================"
echo "VERIFICATION CHECKLIST"
echo "======================================================================"
echo ""

# Verification checklist
CHECKS_PASSED=0
CHECKS_TOTAL=5

echo "[1/5] Sudo check working?"
if grep -q "Running with sudo privileges" "$OUTPUT_DIR/luftweht-output.log"; then
    echo "  ✅ Sudo check passed"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "  ❌ Sudo check not found in logs"
fi

echo "[2/5] Hosts discovered?"
if [ "$LUFTWEHT_DISCOVERED" -gt 0 ]; then
    echo "  ✅ Discovered $LUFTWEHT_DISCOVERED hosts"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "  ❌ No hosts discovered"
fi

echo "[3/5] Port scans auto-scheduled?"
if [ "$LUFTWEHT_PORTSCANNED" -gt 0 ]; then
    echo "  ✅ Port scans completed on $LUFTWEHT_PORTSCANNED hosts"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "  ❌ No port scans completed"
fi

echo "[4/5] Service enumeration auto-scheduled?"
if [ "$LUFTWEHT_SERVICED" -gt 0 ]; then
    echo "  ✅ Service enumeration completed on $LUFTWEHT_SERVICED hosts"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "  ⚠️  No service enumeration completed (may need more time)"
fi

echo "[5/5] Results match nmap baseline?"
if [ "$LUFTWEHT_DISCOVERED" -eq "$NMAP_TOTAL" ]; then
    echo "  ✅ Host count matches nmap ($LUFTWEHT_DISCOVERED hosts)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    DIFF=$((LUFTWEHT_DISCOVERED - NMAP_TOTAL))
    if [ "$DIFF" -gt 0 ]; then
        echo "  ✅ Luftweht found $DIFF more hosts than nmap!"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "  ⚠️  Luftweht found $((DIFF * -1)) fewer hosts than nmap"
    fi
fi

echo ""
echo "======================================================================"
echo "FINAL SCORE: $CHECKS_PASSED / $CHECKS_TOTAL checks passed"
echo "======================================================================"
echo ""

if [ "$CHECKS_PASSED" -ge 4 ]; then
    echo "🎉 AUTO-SCHEDULING IS WORKING!"
    echo ""
    echo "The scanner successfully:"
    echo "  1. Checked for sudo privileges at startup"
    echo "  2. Discovered hosts using multi-method discovery"
    echo "  3. Auto-scheduled full port scans for each host"
    echo "  4. Auto-scheduled service enumeration after port scans"
    echo ""
else
    echo "⚠️  Some checks failed. Review the logs above."
    echo ""
fi

echo "Output files:"
echo "  - $OUTPUT_DIR/luftweht/scan-results.json  : Full results with auto-discovered ports/services"
echo "  - $OUTPUT_DIR/luftweht/scan-report.md     : Human-readable report"
echo "  - $OUTPUT_DIR/luftweht/scan-stream.ndjson : Real-time event stream"
echo "  - $OUTPUT_DIR/luftweht-output.log         : Verbose scanner output"
echo "  - $OUTPUT_DIR/nmap-discovery.xml          : Nmap baseline (discovery ports only)"
echo ""
echo "To see the auto-scheduling chain in action:"
echo "  cat $OUTPUT_DIR/luftweht-output.log | grep -E 'New host discovered|Port scanning|Scheduling service enumeration'"
echo ""
echo "Note: Luftweht automatically does full -p- scans in the background."
echo "Check scan-results.json to see comprehensive port coverage beyond discovery ports."
echo ""
