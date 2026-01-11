# 📋 Development Tasks - Phase 2

## Architecture Overview

```
Attacker → [Firewall Layer] → [Webapp + ML Layer] → Database
                ↑                      ↓
                └──── Feedback Loop ←──┘
```

Run with: `py webapp.py --case N` where N = 1 (no defense), 2 (ML only), 3 (full pipeline)

---

## 🔴 Attack Layer

**File:** `src/offensive/attacker.py`  
**Class:** `QLearningAttackAgent`

### TODO: `mutate_payload()`

```python
def mutate_payload(self, payload):
    # TODO(attack_layer): Add new strategies:
    # - Hex encoding: ' -> 0x27
    # - Double encoding: %27 -> %2527  
    # - Unicode: SELECT -> %u0053ELECT
```

**Test:**
```bash
cd src/offensive && py attacker.py
```

**Goal:** Bypass rate > 30% against Case 2

---

## 🔵 ML Detection Layer

**File:** `src/defensive/detector.py`  
**Class:** `RandomForestDetector`

### TODO: `extract_features()`

```python
def extract_features(self, payload):
    # TODO(ml_detection_layer): Improve extraction:
    # - Character n-grams (3-5)
    # - SQL keyword counts (UNION, SELECT, --, etc.)
    # - Encoding pattern detection (%27, 0x27, etc.)
```

**Test:**
```bash
cd src/defensive && py train.py && py detector.py
```

**Goal:** Detection confidence > 95%

---

## 🟢 Firewall Layer

**File:** `src/firewall/firewall.py`  
**Class:** `SmartFirewall`

### TODO: `match_pattern()`

```python
def match_pattern(self, payload):
    # TODO(firewall_layer): Use regex:
    # - re.IGNORECASE for case variations
    # - Whitespace normalization
    # - Regex patterns instead of exact strings
```

**Test:**
```bash
cd src/firewall && py firewall.py
```

**Goal:** Block obfuscated variants of known patterns

---

## Quick Start

```bash
# Start all services
cd src/defensive && py detector.py   # Terminal 1
cd src/firewall && py firewall.py    # Terminal 2
cd src/webapp && py webapp.py --case 3  # Terminal 3

# Run attack
cd src/offensive && py demo_exploit.py --direct
```
