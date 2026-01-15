#!/bin/bash
CASE=${1:-0}

pkill -f "detector.py" 2>/dev/null
pkill -f "firewall.py" 2>/dev/null
sleep 1

echo "============================================"
echo "  DEFENSE SERVICES - Case $CASE (VERBOSE)"
echo "============================================"

case $CASE in
    0)
        echo "Mode: PASSTHROUGH (No Defense)"
        ;;
    1)
        echo "Mode: ML ONLY"
        ;;
    2)
        echo "Mode: FIREWALL + ML (Full Pipeline)"
        ;;
esac
echo "============================================"
echo ""

if [ "$CASE" = "1" ] || [ "$CASE" = "2" ]; then
    echo "Starting ML Detector (foreground logging)..."
    cd /media/sf_src/defensive
    python3 detector.py &
    DETECTOR_PID=$!
    echo "Detector PID: $DETECTOR_PID"
    sleep 2
fi

echo "Starting Firewall (foreground logging)..."
cd /media/sf_src/firewall
python3 firewall.py --case $CASE

echo ""
echo "Services stopped."
