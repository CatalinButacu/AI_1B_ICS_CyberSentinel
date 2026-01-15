#!/bin/bash
# Stop all Defense Services
# Run this on the Defense machine (10.0.0.10)

echo "Stopping Defense Services..."

pkill -f "detector.py" 2>/dev/null
pkill -f "firewall.py" 2>/dev/null

sleep 1

# Verify stopped
if pgrep -f "firewall.py" > /dev/null; then
    echo "Warning: firewall.py still running"
else
    echo "✓ Firewall stopped"
fi

if pgrep -f "detector.py" > /dev/null; then
    echo "Warning: detector.py still running"
else
    echo "✓ Detector stopped"
fi

echo ""
echo "All services stopped."
echo "Webapp is now unprotected (if still running)."
