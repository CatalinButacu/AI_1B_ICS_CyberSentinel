# ICS Security Project - Adaptive SQL Injection Defense & Attack

A complete adversarial AI system demonstrating automated SQL injection attacks and intelligent defense mechanisms. Built by a 3-person team as a cybersecurity demonstration.

## Team Contributions

| Member | Component | Technology |
|--------|-----------|------------|
| **Radu** | Offensive Agent | Hybrid RL-BiLSTM (PyTorch) |
| **Beatrice** | ML Detector | CNN Classifier (TensorFlow) |
| **Cătălin** | Smart Firewall | Pattern Learning + Snort Rules |

## System Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│   Attacker  │────▶│   Firewall   │────▶│ ML Detector │────▶│  Webapp  │
│   (Radu)    │     │  (Cătălin)   │     │ (Beatrice)  │     │ (Target) │
└─────────────┘     └──────┬───────┘     └──────┬──────┘     └──────────┘
                          │                    │
                          └──── Learns ◀───────┘
                          (Generates Snort Rules)
```

## Defense Modes

| Case | Mode | Description |
|------|------|-------------|
| 0 | Passthrough | No defense - attacks succeed |
| 1 | ML Only | AI detector blocks known patterns |
| 2 | Full Pipeline | Firewall + AI + Adaptive Learning |

## Quick Start

### On VM (Production)
```bash
# Defense VM (10.0.0.10)
cd /media/sf_src
./start_defense.sh 2

# Target VM (10.0.0.20)
./start_webapp.sh

# Kali VM (10.0.0.100)
./run_attack.sh
```

### On Desktop (Local Testing)
```bash
# Set environment
set ICS_ENV=local

# Terminal 1: Detector
cd src/defensive && py detector.py

# Terminal 2: Firewall
cd src/firewall && py firewall.py --case 2

# Terminal 3: Webapp
cd src/webapp && py webapp.py

# Terminal 4: Attack
cd src/offensive && py demo_exploit.py
```

## Project Structure

```
src/
├── offensive/          # Radu's AI Attack Agent
│   ├── attacker.py     # Hybrid RL-BiLSTM
│   ├── rl_attacker/    # Q-Learning module
│   └── bilstm_sqli/    # BiLSTM generator
│
├── defensive/          # Beatrice's ML Detector
│   ├── detector.py     # CNN/RandomForest API
│   └── models/         # Trained models
│
├── firewall/           # Cătălin's Smart Firewall
│   ├── firewall.py     # Main logic
│   ├── patterns.py     # DBSCAN clustering
│   ├── rules.py        # Snort rule generation
│   └── rules/          # Generated .rules files
│
├── webapp/             # Vulnerable target
│   └── webapp.py       # E-Shop with SQL injection
│
└── shared/             # Common utilities
    ├── config.py       # Environment config
    └── interfaces.py   # Abstract classes
```

## How Adaptive Defense Works

```
Attack 1: "' OR 1=1--"
  → Firewall: No pattern match → Forward to ML
  → ML Detector: Attack (92%) → BLOCK
  → Firewall: Learn pattern → Generate Snort rule

Attack 2: "' OR 1=1--"
  → Firewall: Pattern match! → BLOCK immediately
  → ML never called (faster response)
```

## Key Features

- **Offensive AI**: RL agent learns WAF evasion through trial and error
- **Defensive AI**: CNN detects SQLi with 95%+ accuracy
- **Adaptive Firewall**: Learns from attacks, generates rules automatically
- **Real-time Logging**: Wireshark-style traffic visualization

## Requirements

```bash
pip install flask scikit-learn requests numpy
# For offensive module:
pip install torch
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DeepSQLi Paper](https://arxiv.org/abs/2006.02654)
- [Snort Rules](https://www.snort.org/documents)
