# Offensive Module - SQL Injection Attack Agent

Author: Radu

## 📌 Weekly Task (New!)
> **Implement mutation logic in `mutate_payload` method.**
> See [TASKS.md](../../TASKS.md) for details.

## What Is Implemented

### Core Components

**attacker.py** - Reinforcement Learning attack agent that:
- Uses Q-Learning to learn which payload mutations bypass detection
- Implements 6 mutation operators (URL encoding, SQL comments, case mixing, whitespace, newlines, null bytes)
- Sends attacks through the firewall pre-filter endpoint
- Tracks bypass statistics and successful payloads

### Mutation Operators

| Operator | Example | Purpose |
|----------|---------|---------|
| URL Encode | ' -> %27 | Bypass string matching |
| SQL Comments | SELECT -> SEL/**/ECT | Break keyword detection |
| Case Mixing | select -> SeLeCt | Evade case-sensitive rules |
| Whitespace | OR -> OR (extra spaces) | Alter pattern structure |
| Newlines | UNION SELECT -> UNION\nSELECT | Multi-line evasion |
| Null Bytes | ' -> '%00 | Bypass string termination |

### Attack Flow

```
1. Select base payload from SQLI_PAYLOADS list
2. Convert payload to state representation (length, special chars, keywords)
3. Select mutation action based on Q-table (explore vs exploit)
4. Apply mutation to payload
5. Send to firewall /filter endpoint
6. Receive reward: +10 (bypass) or -1 (detected)
7. Update Q-table with learned value
8. Repeat for multiple episodes
```

## How To Run

```bash
cd src/offensive
pip install -r requirements.txt
py attacker.py
```

Requires: Firewall running on localhost:5001

## Future Development Directions

### Short Term
- [ ] Load payloads from external dataset (PayloadsAllTheThings)
- [ ] Add more mutation operators (hex encoding, double encoding)
- [ ] Implement payload chaining (multiple mutations per step)

### Medium Term
- [ ] Replace Q-Learning with Deep Q-Network (DQN) for better generalization
- [ ] Add blind SQL injection support (time-based detection)
- [ ] Implement UNION SELECT data extraction phase

### Long Term
- [ ] Integrate with DeepSQLi approach (sequence-to-sequence model)
- [ ] Add support for other injection types (XSS, Command Injection)
- [ ] Adversarial training loop with detector

## Configuration

Edit `src/shared/config.py`:
```python
FIREWALL_URL = "http://localhost:5001"  # Target endpoint
API_TIMEOUT = 5                          # Request timeout
```

## References

- DeepSQLi Paper: https://arxiv.org/abs/2006.02654
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
