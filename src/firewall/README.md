# Smart Firewall Module

## Architecture Overview

```
                    ┌─────────────────────────────────────────────────┐
                    │                  FIREWALL                        │
                    │                                                  │
  Attack Payload    │   ┌──────────┐    ┌──────────┐    ┌──────────┐  │   Webapp
 ──────────────────►│   │  PATTERN │───►│    ML    │───►│  TARGET  │──┼──►Response
  (from Kali)       │   │  MATCH   │    │ DETECTOR │    │ FORWARD  │  │
                    │   └────┬─────┘    └────┬─────┘    └──────────┘  │
                    │        │               │                        │
                    │        │ no match      │ attack detected        │
                    │        ▼               ▼                        │
                    │   continue        ┌────────────┐                │
                    │                   │  FEEDBACK  │                │
                    │                   │    LOOP    │                │
                    │                   └─────┬──────┘                │
                    │                         │                       │
                    │                         ▼                       │
                    │                   ┌────────────┐                │
                    │                   │ CLUSTERING │                │
                    │                   └─────┬──────┘                │
                    │                         │                       │
                    │                         ▼                       │
                    │                   ┌────────────┐                │
                    │                   │   SNORT    │                │
                    │                   │   RULES    │                │
                    │                   └────────────┘                │
                    └─────────────────────────────────────────────────┘
```

---

## Entry Point: firewall.py

### Main Function Flow

```python
main()
    │
    ├── Parse arguments (--case 0/1/2)
    │
    ├── Create SmartFirewall(case_number)
    │
    └── Start Flask server on port 5001
            │
            └── /filter endpoint receives all traffic
```

### Case Modes

| Case | Name | Pattern Check | ML Check | Learning |
|------|------|---------------|----------|----------|
| 0 | PASSTHROUGH | ❌ | ❌ | ❌ |
| 1 | ML_ONLY | ❌ | ✅ | ❌ |
| 2 | FULL_PIPELINE | ✅ | ✅ | ✅ |

---

## Request Processing: /filter Endpoint

### Case 0: Passthrough

```
Payload → forward_to_webapp() → Response
          (no checks)
```

### Case 1: ML Only

```
Payload → send_to_ml_detector()
              │
              ├── is_attack=True → BLOCKED
              │
              └── is_attack=False → forward_to_webapp() → Response
```

### Case 2: Full Pipeline

```
Payload → payload_matches_known_pattern()
              │
              ├── match=True → BLOCKED (instant, no ML needed)
              │
              └── match=False → send_to_ml_detector()
                                    │
                                    ├── is_attack=True
                                    │       │
                                    │       ├── BLOCKED
                                    │       │
                                    │       └── add_payload_to_collection()
                                    │               │
                                    │               └── extract_and_learn_patterns()
                                    │                       │
                                    │                       └── create_snort_rules()
                                    │
                                    └── is_attack=False → forward_to_webapp()
```

---

## Pattern Learning: Feedback Loop

### Step 1: Collect Payloads

```python
add_payload_to_collection(payload)
    │
    ├── Store in collected_payloads[]
    │
    └── If count >= MIN_PAYLOADS_FOR_CLUSTERING
            │
            └── extract_and_learn_patterns()
```

### Step 2: Extract Patterns (patterns.py)

```python
AttackPatternExtractor.extract_attack_patterns(payloads)
    │
    ├── Method 1: Frequent Substring Analysis
    │       │
    │       ├── Find common substrings across all payloads
    │       │
    │       └── Filter by min_occurrence_ratio (default: 30%)
    │
    └── Method 2: DBSCAN Clustering
            │
            ├── Convert payloads to TF-IDF vectors
            │
            ├── Cluster similar payloads together
            │
            └── Extract common pattern from each cluster
```

### Step 3: Generate Snort Rules (rules.py)

```python
create_snort_rule_from_pattern(pattern)
    │
    ├── Generate unique SID (hash-based)
    │
    ├── Escape special characters
    │
    └── Build rule:
        alert tcp any any -> any any (
            msg:"AI-Learned: {pattern}";
            content:"{escaped_pattern}";
            nocase;
            sid:{unique_sid};
        )
```

---

## File Structure

```
firewall/
├── firewall.py          # Main Flask server, request routing
├── patterns.py          # Pattern extraction, clustering logic
├── rules.py             # Snort rule generation
├── data/
│   ├── collected_payloads.json    # Raw attack payloads
│   └── learned_patterns.json      # Extracted patterns
└── rules/
    └── ai_learned.rules           # Generated Snort rules
```

---

## Class: SmartFirewall

### Properties

| Property | Type | Description |
|----------|------|-------------|
| case_number | int | 0, 1, or 2 |
| is_passthrough | bool | case_number == 0 |
| is_ml_only | bool | case_number == 1 |
| is_full_pipeline | bool | case_number == 2 |
| collected_payloads | list | Payloads waiting for clustering |
| learned_patterns | list | Patterns for instant blocking |
| stats | dict | Counters for monitoring |

### Methods

| Method | Purpose |
|--------|---------|
| load_stored_data() | Load patterns/payloads from JSON files |
| save_stored_data() | Persist to JSON files |
| normalize_for_matching(text) | Lowercase, remove SQL comments, normalize whitespace |
| payload_matches_known_pattern(payload) | Check if matches any learned pattern |
| match_pattern(payload) | Alias for abstract class compatibility |
| add_payload_to_collection(payload) | Store + trigger clustering if threshold met |
| extract_and_learn_patterns() | Run clustering and generate rules |

---

## Class: AttackPatternExtractor

### Clustering Algorithm

```
Input: ["' OR 1=1--", "' OR 2=2--", "' UNION SELECT..."]
                │
                ▼
        TF-IDF Vectorization (char n-grams)
                │
                ▼
        DBSCAN Clustering (cosine distance)
                │
                ▼
        Extract common substrings per cluster
                │
                ▼
Output: [{"pattern": "' OR", "frequency": 0.75}, ...]
```

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| min_pattern_length | 3 | Minimum chars for pattern |
| min_occurrence_ratio | 0.3 | Pattern must appear in 30%+ of payloads |
| distance_threshold | 0.5 | DBSCAN epsilon for clustering |
| min_cluster_size | 2 | Minimum payloads per cluster |

---

## Snort Integration

### Rule Format

```
alert tcp any any -> any any (
    msg:"AI-Learned: {preview}";
    flow:to_server,established;
    content:"{escaped_pattern}";
    nocase;
    classtype:web-application-attack;
    sid:{unique_sid};
    rev:1;
    metadata:created {date};
)
```

### Rule Management

```bash
# View generated rules
cat rules/ai_learned.rules

# Reset all rules
curl -X POST http://10.0.0.10:5001/reset

# Get current patterns
curl http://10.0.0.10:5001/patterns
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /filter | POST | Main entry point for traffic |
| /feedback | POST | Manual pattern submission |
| /status | GET | Stats and configuration |
| /patterns | GET | List learned patterns |
| /reset | POST | Clear all learned data |
| /check | POST | Check pattern match only |

---

## Example: Full Attack Cycle

```
1. Attacker sends: ' UNION SELECT 1, username, password FROM users--
                        │
                        ▼
2. Firewall receives at /filter
                        │
                        ▼
3. Pattern check: NOT in learned_patterns (first time)
                        │
                        ▼
4. Forward to ML Detector → is_attack=True (88% confidence)
                        │
                        ▼
5. BLOCKED + payload stored in collected_payloads
                        │
                        ▼
6. Threshold reached → run clustering
                        │
                        ▼
7. Pattern extracted: "UNION SELECT"
                        │
                        ▼
8. Snort rule generated and saved
                        │
                        ▼
9. NEXT attack with "UNION SELECT" → BLOCKED INSTANTLY by firewall
   (no ML call needed)
```

---

## Performance Benefits

| Stage | Latency | Resource Usage |
|-------|---------|----------------|
| Pattern Match | ~1ms | Very Low |
| ML Detection | ~50-200ms | Medium (CPU) |
| Clustering | ~100-500ms | High (one-time) |

After learning, attacks are blocked in ~1ms instead of ~200ms.
