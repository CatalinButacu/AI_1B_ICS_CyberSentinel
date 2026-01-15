#!/bin/bash
# Start Radu's AI Attack Agent
# Run this on the Kali machine (10.0.0.100)

echo "============================================"
echo "  RADU'S AI ATTACK AGENT"
echo "  Hybrid RL-BiLSTM SQL Injection"
echo "============================================"
echo ""

cd /media/sf_src/offensive

# Check if dependencies exist
if ! python3 -c "import torch" 2>/dev/null; then
    echo "[WARN] PyTorch not installed. Installing..."
    pip3 install torch --break-system-packages
fi

echo "[INFO] Target: http://10.0.0.10:5001/filter"
echo "[INFO] Starting AI Attack Agent..."
echo ""

python3 attacker.py
