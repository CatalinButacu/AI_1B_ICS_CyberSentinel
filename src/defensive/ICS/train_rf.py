import pandas as pd
import numpy as np
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import recall_score, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline

# --- CONFIGURATION ---
DATA_PATH = 'labeled_dataset.csv'


def train():
    if not os.path.exists(DATA_PATH):
        print("Error: labeled_dataset.csv not found.")
        return

    df = pd.read_csv(DATA_PATH)

    X = df['query'].values
    y = df['label'].values

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1, 3))),
        ('rf', RandomForestClassifier(n_estimators=100, n_jobs=-1, verbose=1))
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    recall = recall_score(y_test, y_pred)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Accuracy: {acc:.4f}")
    print(f"Recall:   {recall:.4f}")
    print("Confusion Matrix:")
    print(cm)

    # Save
    with open('rf_model_dirty.pkl', 'wb') as f:
        pickle.dump(pipeline, f)

if __name__ == "__main__":
    train()