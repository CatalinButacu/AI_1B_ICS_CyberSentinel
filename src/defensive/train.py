import pandas as pd
import numpy as np
import pickle
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.utils import class_weight
from sklearn.metrics import recall_score, confusion_matrix
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

SHARED_DATASET_PATH = os.path.join(BASE_DIR, '..', 'shared', 'datasets', 'labeled_dataset.csv')
LOCAL_DATASET_PATH = os.path.join(BASE_DIR, 'labeled_dataset.csv')

vocab_size = 10000
max_length = 100
dim = 32


def train():
    # Determine dataset path
    if os.path.exists(SHARED_DATASET_PATH):
        dataset_path = SHARED_DATASET_PATH
    elif os.path.exists(LOCAL_DATASET_PATH):
        dataset_path = LOCAL_DATASET_PATH
    else:
        # Fallback to sqli_dataset if labeled_dataset not found
        dataset_path = os.path.join(BASE_DIR, '..', 'shared', 'datasets', 'sqli_dataset.csv')
        print(f"labeled_dataset.csv not found, checking {dataset_path}")
        if not os.path.exists(dataset_path):
             print("Error: No dataset found.")
             return

    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    if 'Query' in df.columns: df.rename(columns={'Query': 'query'}, inplace=True)
    if 'Label' in df.columns: df.rename(columns={'Label': 'label'}, inplace=True)

    X = df['query'].astype(str)
    y = df['label'].values

    # Tokenizer - Character level=False to capture words like 'SELECT' or 'UNION'
    tokenizer = Tokenizer(num_words=vocab_size, char_level=False, lower=True)
    tokenizer.fit_on_texts(X)

    # Save tokenizer
    tokenizer_path = os.path.join(MODELS_DIR, 'tokenizer.pickle')
    with open(tokenizer_path, 'wb') as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"Tokenizer saved to {tokenizer_path}")

    # Convert text to sequences
    sequences = tokenizer.texts_to_sequences(X)
    X_padded = pad_sequences(sequences, maxlen=max_length)

    X_train, X_test, y_train, y_test = train_test_split(X_padded, y, test_size=0.2, random_state=42)

    # Calculate weights to prioritize Recall
    weights = class_weight.compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weights = {0: weights[0], 1: weights[1] * 1.5}  # Boost attack weight slightly

    # CNN model
    model = Sequential([
        Embedding(vocab_size, dim, input_length=max_length),

        Conv1D(filters=64, kernel_size=3, activation='relu'),
        GlobalMaxPooling1D(),

        Dense(32, activation='relu'),
        Dropout(0.5),  # Prevent overfitting
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_test, y_test), class_weight=class_weights)

    # evaluation
    y_pred_prob = model.predict(X_test)

    #lower threshold for catching attacks
    y_pred = (y_pred_prob > 0.2).astype(int)

    recall = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("Confusion Matrix:\n", cm)
    print(f"Recall:  {recall:.4f}.")
    
    model_save_path = os.path.join(MODELS_DIR, 'sqli_cnn.h5') 
    model.save(model_save_path)
    print(f"Model saved to {model_save_path}")


if __name__ == "__main__":
    train()
