# ICS AI Security Project - Quick Start Guide

## 🚀 Run the Complete PoC in 3 Steps

### Prerequisites
- Python 3.8+
- pip

### Step 1: Install Dependencies (run from project root)

```bash
# Install all dependencies
pip install flask pandas scikit-learn numpy requests
```

Or per module:
```bash
cd offensive && pip install -r requirements.txt && cd ..
cd defensive && pip install -r requirements.txt && cd ..
cd firewall && pip install -r requirements.txt && cd ..
```

---

### Step 2: Start Services (in order)

**Terminal 1 - Beatrice (Detector):**
```bash
cd defensive
python train_model.py      # First time only: trains the model
python detector_api.py     # Starts API on localhost:5000
```

**Terminal 2 - Catalin (Firewall):**
```bash
cd firewall
python feedback_receiver.py  # Starts API on localhost:5001
```

**Terminal 3 - Radu (Attacker):**
```bash
cd offensive
python rl_attack_agent.py    # Starts attack
```

---

### Step 3: See Results

After Radu's attack runs:
- Beatrice console shows detected attacks
- Catalin console shows received feedback
- Check `firewall/rules/ai_learned.rules` for generated Snort rules

---

## 📊 API Quick Reference

### Beatrice (localhost:5000)
```bash
# Check payload
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"payload": "'"'"' OR 1=1--"}'

# Health check
curl http://localhost:5000/health
```

### Catalin (localhost:5001)
```bash
# Check status
curl http://localhost:5001/status

# View rules
curl http://localhost:5001/rules

# Force rule generation
curl -X POST http://localhost:5001/generate
```

---

## 📁 Project Structure

```
ICS/
├── offensive/           # 🔴 RADU
│   ├── rl_attack_agent.py   # RL attack agent
│   └── requirements.txt
│
├── defensive/           # 🟢 BEATRICE
│   ├── train_model.py       # Model training
│   ├── detector_api.py      # Detection API
│   └── requirements.txt
│
├── firewall/            # 🔵 CATALIN
│   ├── feedback_receiver.py # Feedback API
│   ├── pattern_extractor.py # DBSCAN clustering
│   ├── rule_generator.py    # Snort rules
│   └── requirements.txt
│
├── shared/              # Common config
│   ├── config.py
│   └── utils.py
│
└── QUICKSTART.md        # This file
```

---

## 🔄 System Flow

```
Radu (Attack) ──────► Beatrice (Detect) ──────► Catalin (Learn)
                            │                        │
                            │ feedback               │ generates
                            ▼                        ▼
                    blocks attack           Snort rules
```

---

## ❓ Troubleshooting

**"Connection refused"**: Make sure services are running in order: Beatrice → Catalin → Radu

**"Model not found"**: Run `python train_model.py` first in defensive/

**"No payloads collected"**: Let Radu attack for a bit, then check Catalin's status
