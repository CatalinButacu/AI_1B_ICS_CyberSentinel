"""
SQL Injection Detection Model Training
Author: Beatrice (Defensive Team)

TODO: Download Kaggle dataset (30k samples) from https://www.kaggle.com/datasets/sajid576/sql-injection-dataset
TODO: Try XGBoost (99.58% accuracy reported in research)
TODO: Add BERT-LSTM for semantic understanding
"""

import os
import sys
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import RESOURCES

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
DATASET_PATH = os.path.join(os.path.dirname(__file__), '..', 'shared', 'datasets', 'sqli_dataset.csv')
MODEL_PATH = os.path.join(MODELS_DIR, 'sqli_detector.pkl')


def create_sample_training_data():
    print("[WARN] Using sample dataset - download real data from Kaggle!")
    
    attacks = [
        "' OR 1=1--", "' OR '1'='1", "admin'--", "' UNION SELECT NULL--",
        "' UNION SELECT username, password FROM users--", "1' AND 1=1--",
        "' OR 'a'='a", "'; DROP TABLE users;--", "' AND SLEEP(5)--",
        "1' ORDER BY 1--", "' OR 1=1#", "admin' --", "' UNION ALL SELECT NULL--",
        "' AND 1=CONVERT(int,@@version)--", "1; EXEC xp_cmdshell('dir')--",
        "' OR ''='", "'-'", "' AND '1'='1", "') OR ('1'='1", "' OR 1=1 /*",
    ]
    
    normal = [
        "john.doe@email.com", "password123", "Search products", "Hello World",
        "user_name_123", "My name is John", "Order #12345", "contact@company.com",
        "Welcome to website", "Product description", "username", "admin",
        "test123", "hello", "support@example.com", "New York", "12345",
        "John Smith", "Category: Electronics", "Price: $99.99",
    ]
    
    data = [{'Query': p, 'Label': 1} for p in attacks]
    data += [{'Query': t, 'Label': 0} for t in normal]
    
    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    
    return df


def load_training_data():
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found. Download from: {RESOURCES['datasets']['sqli_kaggle']}")
        return create_sample_training_data()
    
    df = pd.read_csv(DATASET_PATH)
    
    if 'Query' not in df.columns and 'query' in df.columns:
        df = df.rename(columns={'query': 'Query'})
    if 'Label' not in df.columns and 'label' in df.columns:
        df = df.rename(columns={'label': 'Label'})
    
    return df


def train_sqli_classifier(training_data):
    queries = training_data['Query'].fillna('').values
    labels = training_data['Label'].values
    
    print(f"Training samples: {len(queries)}")
    print(f"Attack ratio: {labels.mean():.1%}")
    
    text_vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(2, 5),
        max_features=5000,
        lowercase=True
    )
    query_vectors = text_vectorizer.fit_transform(queries)
    
    X_train, X_test, y_train, y_test = train_test_split(
        query_vectors, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    classifier.fit(X_train, y_train)
    
    predictions = classifier.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    
    print(f"\nAccuracy: {accuracy:.1%}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=['Normal', 'Attack']))
    
    return classifier, text_vectorizer


def save_trained_model(classifier, vectorizer):
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    model_bundle = {'model': classifier, 'vectorizer': vectorizer}
    
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model_bundle, f)
    
    print(f"Model saved: {MODEL_PATH}")


def main():
    print("="*60)
    print("SQL INJECTION DETECTOR - MODEL TRAINING")
    print("="*60 + "\n")
    
    training_data = load_training_data()
    classifier, vectorizer = train_sqli_classifier(training_data)
    save_trained_model(classifier, vectorizer)
    
    print("\nTraining complete. Run detector_api.py to start the API.")


if __name__ == "__main__":
    main()
