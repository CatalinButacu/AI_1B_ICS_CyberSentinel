# Shared Module

Core business logic and configuration.

## Files

| File | Purpose |
|------|---------|
| `pipeline.py` | Defense orchestrator - implements all 3 cases |
| `interfaces.py` | Abstract classes: `BaseAttacker`, `BaseDetector`, `BaseFirewall` |
| `config.py` | URLs, ports, timeouts |

## DefensePipeline

```python
from shared.pipeline import DefensePipeline

pipeline = DefensePipeline(case=3)
is_allowed, reason, details = pipeline.check_request(user_input)

if not is_allowed:
    return None  # Block
```

## Configuration

```python
# config.py
DETECTOR_URL = "http://localhost:5000"
FIREWALL_URL = "http://localhost:5001"
WEBAPP_URL = "http://localhost:5002"
API_TIMEOUT = 5
```
