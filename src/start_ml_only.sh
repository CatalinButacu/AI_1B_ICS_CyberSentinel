#!/bin/bash
# Start ONLY ML Detection (no Firewall)
# Run this on the Defense machine (10.0.0.10)

echo "Starting ML Detection ONLY..."

# Stop firewall if running
pkill -f "firewall.py" 2>/dev/null

# Start Detector
cd /media/sf_src/defensive
python3 detector.py &
echo "Detector started: http://10.0.0.10:5000"
echo ""
echo "Webapp will run in Case 2 (ML Detection Only)"
