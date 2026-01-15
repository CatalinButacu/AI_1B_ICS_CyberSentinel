import pandas as pd
import numpy as np
import pickle
import tensorflow as tf
import re
import os
from urllib.parse import unquote
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.metrics import recall_score, confusion_matrix

# --- CONFIGURATION ---
DATA_PATH = 'labeled_dataset.csv'
VOCAB_SIZE = 10000
MAX_LEN = 100
EMBEDDING_DIM = 32


def clean_query(query_text):
    if not isinstance(query_text, str):
        return ""

    # 1. URL Decode (Handles %09, %0A, %20)
    # This fixes "Whitespace encoding: space -> %09"
    query_text = unquote(query_text)

    # 2. Hex Decoding (Handles 0x64626f -> dbo)
    # This fixes "Hex encoding: 'admin' -> 0x..."
    def hex_to_text(match):
        try:
            # Convert hex string to bytes, then to utf-8 text
            return bytearray.fromhex(match.group(1)).decode('utf-8', errors='ignore')
        except:
            return match.group(0)  # If fails, return original 0x123

    query_text = re.sub(r'0x([0-9a-fA-F]+)', hex_to_text, query_text)

    # 3. Comment Removal (Handles Keyword splitting)
    # Turns "SE/**/LECT" -> "SELECT"
    query_text = re.sub(r'/\*.*?\*/', '', query_text)

    # 4. Symbol Splitting (Handles Comment variations --, #, ;)
    # Turns "admin'#" -> "admin ' #"
    query_text = re.sub(r'([^\w\s])', r' \1 ', query_text)

    # 5. Normalize whitespace
    query_text = " ".join(query_text.split())

    return query_text


def train():
    print(f"1. Loading Dataset ")

    if not os.path.exists(DATA_PATH):
        print("ERROR: File not found. Please verify the path.")
        return

    df = pd.read_csv(DATA_PATH)

    print("2. Preprocessing")
    df['query'] = df['query'].apply(clean_query)

    X_raw = df['query'].values
    y = df['label'].values

    # Tokenization
    print("3. Tokenizing")
    tokenizer = Tokenizer(num_words=VOCAB_SIZE, char_level=False, lower=True)
    tokenizer.fit_on_texts(X_raw)

    #save
    with open('tokenizer.pickle', 'wb') as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

    sequences = tokenizer.texts_to_sequences(X_raw)
    X_padded = pad_sequences(sequences, maxlen=MAX_LEN)

    X_train, X_test, y_train, y_test = train_test_split(X_padded, y, test_size=0.2, random_state=42)

    #model
    print("4. Training CNN")
    model = Sequential([
        Embedding(VOCAB_SIZE, EMBEDDING_DIM, input_length=MAX_LEN),
        Conv1D(filters=64, kernel_size=3, activation='relu'),
        GlobalMaxPooling1D(),
        Dense(32, activation='relu'),
        Dropout(0.5),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=3, batch_size=64, validation_data=(X_test, y_test))

    # eval
    y_pred = (model.predict(X_test) > 0.2).astype(int)
    recall = recall_score(y_test, y_pred)

    print(f"\nFINAL RECALL: {recall:.4f}")
    model.save('sql_model.h5')


if __name__ == "__main__":
    train()