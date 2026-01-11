# Firewall Module - Smart Pre-Filter and Rule Generator

Author: Catalin

## 📌 Weekly Task (New!)
> **Implement regex pattern matching in `match_pattern` method.**
> See [TASKS.md](../../TASKS.md) for details.

## What Is Implemented

### Core Components

**firewall.py** - Main API with smart pre-filter that:
- Checks incoming payloads against learned patterns (instant block)
- Forwards unknown payloads to detector for ML classification
- Learns new patterns from detected attacks
- Generates Snort IDS rules automatically

**patterns.py** - Pattern extraction using:
- DBSCAN clustering to group similar attack payloads
- Longest common substring extraction
- Frequency analysis for pattern ranking

**rules.py** - Snort rule generation that:
- Converts patterns to valid Snort rule syntax
- Handles special character escaping
- Generates unique SIDs (signature IDs)
- Appends rules to ai_learned.rules file

### Pre-Filter Flow

```
Incoming Request
       |
       v
[Check Learned Patterns] --match--> [BLOCK immediately]
       |
       | no match
       v
[Forward to Detector]
       |
       v
[Attack Detected?] --yes--> [Learn Pattern] --> [Generate Rule]
       |
       | no
       v
[ALLOW request]
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /filter | POST | Main entry - check and route traffic |
| /feedback | POST | Receive attack feedback from detector |
| /patterns | GET | View learned patterns |
| /rules | GET | View generated Snort rules |
| /status | GET | Firewall statistics |
| /clear | POST | Reset all learned data |

### Pattern Learning

When 3+ similar attacks are received:
1. Cluster payloads using DBSCAN (eps=0.3)
2. Extract common substrings from each cluster
3. Filter patterns by minimum length (5 chars)
4. Generate Snort rule for each unique pattern

### Generated Rule Format

```
alert tcp any any -> any any (
    msg:"AI-Detected: SEL/**/ECT";
    content:"SEL/**/ECT";
    nocase;
    classtype:web-application-attack;
    sid:9012345;
    rev:1;
)
```

## How To Run

```bash
cd src/firewall
pip install -r requirements.txt
py firewall.py
```

API runs on: localhost:5001
Requires: Detector running on localhost:5000

## Current Output Files

| File | Location | Purpose |
|------|----------|---------|
| learned_patterns.json | data/ | Patterns for pre-filtering |
| collected_payloads.json | data/ | Attack samples for clustering |
| ai_learned.rules | rules/ | Generated Snort rules |

## Future Development Directions

### Short Term
- [ ] Add pattern deduplication (avoid duplicate rules)
- [ ] Implement pattern effectiveness tracking
- [ ] Add rate limiting per source IP

### Medium Term
- [ ] Replace DBSCAN with Isolation Forest for anomaly detection
- [ ] Add real-time Snort/Suricata rule reloading
- [ ] Implement pattern aging (remove old unused patterns)

### Long Term
- [ ] Integrate with actual Snort/Suricata deployment
- [ ] Add MITRE ATT&CK technique tagging
- [ ] Support distributed pattern sharing between instances

## Configuration

Edit `src/shared/config.py`:
```python
FIREWALL_URL = "http://localhost:5001"
DETECTOR_URL = "http://localhost:5000"
```

Edit `firewall.py`:
```python
MIN_PAYLOADS_FOR_RULE_GENERATION = 3  # Minimum samples before clustering
```

## Snort Integration

To use generated rules with Snort:

```bash
# Copy rules to Snort config
cp src/firewall/rules/ai_learned.rules /etc/snort/rules/

# Add to snort.conf
echo 'include $RULE_PATH/ai_learned.rules' >> /etc/snort/snort.conf

# Reload Snort
sudo snort -c /etc/snort/snort.conf -T
```

## References

- Snort Documentation: https://www.snort.org/documents
- Suricata Rules: https://suricata.readthedocs.io/en/latest/rules/
- DBSCAN Algorithm: https://scikit-learn.org/stable/modules/clustering.html#dbscan
