# Team Contributions

## Project Repository
**Main Repository**: https://github.com/[TEAM_LEADER_USERNAME]/ICS

## Team Members and Contributions

### Radu-Ionuț Bălăiță
**Role**: Offensive Module Developer ([README](file:///c:/Users/catalin.butacu/Downloads/ICS/src/offensive/README.md))

**Contributions**:
- Designed and implemented the BiLSTM Seq2Seq architecture for payload mutation
- Developed the Q-Learning reinforcement learning agent for adaptive mutation selection
- Created the attack script infrastructure for baseline testing
- Trained the offensive model on 10,000 augmented SQLi samples
- Achieved 99.5% WAF bypass rate with the hybrid RL-BiLSTM approach

**Files**:
- `src/offensive/attacker.py`
- `src/offensive/rl_attacker/`
- `src/offensive/bilstm_sqli/`

---

### Ștefana-Beatrice Gherghel
**Role**: Detection Module Developer ([README](file:///c:/Users/catalin.butacu/Downloads/ICS/src/defensive/README.md))

**Contributions**:
- Designed and trained the CNN classifier for SQLi detection
- Implemented the RandomForest fallback model with TF-IDF features
- Conducted comparative analysis between CNN and RandomForest models
- Optimized detection threshold for 95% recall requirement
- Implemented automatic model fallback mechanism

**Files**:
- `src/defensive/detector.py`
- `src/defensive/models/`
- `src/defensive/train_cnn.py`

---

### Ionel-Cătălin Butacu
**Role**: Firewall Module Developer & Team Leader ([README](file:///c:/Users/catalin.butacu/Downloads/ICS/src/firewall/README.md))

**Contributions**:
- Designed the adaptive firewall architecture with three defense modes
- Implemented DBSCAN clustering for attack pattern extraction
- Developed Frequent Substring Analysis for pattern mining
- Created Snort IDS rule generation system
- Implemented rule consolidation to reduce redundancy (53% reduction)
- Built the microservices REST API architecture
- Managed project integration and VM deployment

**Files**:
- `src/firewall/firewall.py`
- `src/firewall/patterns.py`
- `src/firewall/rules.py`
- `src/shared/config.py`

---

## Shared Contributions
- Dataset generation and augmentation (all members)
- Documentation and README files (all members)
- Testing and benchmarking (all members)
- IEEE paper writing (all members)

## Project Statistics
- **Lines of Code**: ~3,000
- **Models Trained**: 3 (BiLSTM, CNN, RandomForest)
- **Snort Rules Generated**: 16 (consolidated from 34)
- **Benchmark Payloads**: 150
- **Recall Achieved**: 95%
- **WAF Bypass Rate**: 99.5%
