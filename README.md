# ICS Security Project - Adaptive SQL Injection Defense

## What This Is

A modular defense system against SQL Injection attacks with 3 configurable defense levels.

```
Attacker ──▶ [Firewall] ──▶ [ML Detector] ──▶ Webapp ──▶ Database
                 │                │              ↑
                 └── Learns ◀─────┘──────────────┘
```

## 3 Defense Modes

| Mode | Command | What Happens |
|------|---------|--------------|
| **Case 1** | `py webapp.py --case 1` | No defense. Fully vulnerable. |
| **Case 2** | `py webapp.py --case 2` | ML checks each request before SQL executes. |
| **Case 3** | `py webapp.py --case 3` | Firewall + ML + Adaptive Learning. |

## Project Structure

```
src/
├── shared/                # Core business logic
│   ├── pipeline.py        # Defense orchestrator (main logic)
│   ├── interfaces.py      # Abstract base classes
│   └── config.py          # URLs and settings
│
├── webapp/                # Vulnerable target
│   └── webapp.py          # E-Shop with --case argument
│
├── defensive/             # ML Detection Layer
│   ├── detector.py        # RandomForest API (port 5000)
│   └── train.py           # Model training
│
├── firewall/              # Firewall Layer
│   └── firewall.py        # Pattern matching API (port 5001)
│
└── offensive/             # Attack simulation
    ├── attacker.py        # Q-Learning agent
    └── demo_exploit.py    # Quick attack demo
```

## Quick Start

```bash
# Install
pip install flask scikit-learn requests

# Run Case 3 (Full Defense)
cd src/defensive && py detector.py   # Terminal 1 (port 5000)
cd src/firewall && py firewall.py    # Terminal 2 (port 5001)
cd src/webapp && py webapp.py --case 3  # Terminal 3 (port 5002)

# Attack
cd src/offensive && py demo_exploit.py --direct
```

## How Case 3 Works

```
1st Attack: "' OR 1=1--"
  → Firewall: No pattern → Forward
  → ML: Attack detected (95%) → BLOCK
  → Firewall learns pattern

2nd Attack: "' OR 1=1--"
  → Firewall: Pattern match! → BLOCK immediately
  → ML never called
```

## Shared Module (Core)

| File | Purpose |
|------|---------|
| `pipeline.py` | `DefensePipeline` class - orchestrates all 3 cases |
| `interfaces.py` | `BaseAttacker`, `BaseDetector`, `BaseFirewall` |
| `config.py` | Service URLs, timeouts, thresholds |

## Development TODOs

Search for these in code:
- `TODO(attack_layer)` → `attacker.py:mutate_payload()`
- `TODO(ml_detection_layer)` → `detector.py:extract_features()`
- `TODO(firewall_layer)` → `firewall.py:match_pattern()`

See `TASKS.md` for detailed instructions.

## API Endpoints

| Service | Port | Key Endpoint |
|---------|------|--------------|
| Detector | 5000 | `POST /check` → `{is_attack, confidence}` |
| Firewall | 5001 | `POST /check-pattern` → `{blocked}` |
| Webapp | 5002 | `POST /login` → Target for attacks |

## References

- [Kaggle SQLi Dataset](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset)
- [DeepSQLi Paper](https://arxiv.org/abs/2006.02654)
- [ML in Cybersecurity](https://arxiv.org/abs/2004.11894)
