#!/bin/bash
# Run Attack from Kali
# Run this on the Attacker machine (10.0.0.100)

echo "╔════════════════════════════════════════════╗"
echo "║     SQL INJECTION ATTACK DEMO              ║"
echo "╠════════════════════════════════════════════╣"
echo "║ Attack Flow:                               ║"
echo "║   Kali → Firewall → Detector → Webapp      ║"
echo "║         (10.0.0.10)           (10.0.0.20)  ║"
echo "╚════════════════════════════════════════════╝"
echo ""

cd /media/sf_src/offensive
python3 demo_exploit.py
