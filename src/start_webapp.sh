#!/bin/bash
# Start Webapp (Vulnerable Target)
# Run this on the Webapp machine (10.0.0.20)

echo "Starting Vulnerable E-Shop..."
echo ""
echo "The webapp will auto-detect Defense services:"
echo "  - If Detector+Firewall running → Case 3"
echo "  - If only Detector running → Case 2"
echo "  - If nothing running → Case 1 (vulnerable)"
echo ""

cd /media/sf_src/webapp
python3 webapp.py
