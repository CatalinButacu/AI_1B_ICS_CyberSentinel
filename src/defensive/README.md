# Defensive Module - SQL Injection Detector

Author: Beatrice

## 📌 Weekly Task (New!)
> **Improve feature extraction (`extract_features`) with N-grams or embeddings.**
> See [TASKS.md](../../TASKS.md) for details.

## What Is Implemented

### Core Components

**train.py** - Model training script that:
- Loads SQL injection dataset (Kaggle or sample data)
- Extracts features using TF-IDF vectorization (character n-grams)
- Trains RandomForest classifier
- Evaluates accuracy and saves model to pickle file

**detector.py** - REST API that:
- Loads trained model on startup
- Exposes /check endpoint for payload classification
- Returns attack probability and confidence score
- Sends detected attacks to firewall for pattern learning

### Machine Learning Pipeline

```
Input Query --> TF-IDF Vectorizer --> Feature Vector --> RandomForest --> Attack/Normal
                (char 2-5 grams)       (5000 dims)        (100 trees)
```

### Feature Extraction

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Analyzer | char | Captures SQL syntax patterns |
| N-gram range | (2, 5) | Detects 'OR', '--', '/*' patterns |
| Max features | 5000 | Balance between coverage and speed |
| Lowercase | True | Case-insensitive detection |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /check | POST | Classify payload, returns is_attack + confidence |
| /health | GET | Service health check |
| /stats | GET | Detection statistics |

## How To Run

```bash
cd src/defensive

# Step 1: Train model
pip install -r requirements.txt
py train.py

# Step 2: Start API
py detector.py
```

API runs on: localhost:5000

## Current Performance

With sample dataset (40 samples):
- Accuracy: 100% (overfitting on small data)
- Training time: < 1 second

Expected with Kaggle dataset (30k samples):
- Accuracy: 96-98%
- Recall: 95%+ (course requirement)

## Future Development Directions

### Short Term
- [ ] Download and integrate Kaggle SQLi dataset (30k samples)
- [ ] Add cross-validation for better accuracy estimation
- [ ] Implement confidence threshold tuning

### Medium Term
- [ ] Replace RandomForest with XGBoost (99.58% accuracy reported)
- [ ] Add ensemble of multiple classifiers
- [ ] Implement online learning (update model with new attacks)

### Long Term
- [ ] Integrate BERT-LSTM for semantic understanding
- [ ] Add explainability (SHAP values for predictions)
- [ ] Support for other attack types (XSS, Command Injection)

## Configuration

Edit `src/shared/config.py`:
```python
DETECTOR_URL = "http://localhost:5000"
FEEDBACK_CONFIDENCE_THRESHOLD = 0.8  # Send to firewall if > 80%
```

## Dataset

Current: Sample data (20 attack + 20 normal queries)

Recommended: Kaggle SQL Injection Dataset
- URL: https://www.kaggle.com/datasets/sajid576/sql-injection-dataset
- Size: 30,000+ labeled queries
- Download to: src/shared/datasets/sqli_dataset.csv

## References

- Apruzzese et al., "ML in Cybersecurity": https://arxiv.org/abs/2004.11894
- Kaggle Dataset: https://www.kaggle.com/datasets/sajid576/sql-injection-dataset
