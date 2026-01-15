import pandas as pd
import numpy as np
import pickle
import tensorflow as tf
import re
import os
from urllib.parse import unquote
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense, Embedding, Dropout

DATA_PATH = 'labeled_dataset.csv'
VOCAB_SIZE = 2000
MAX_LEN = 50
EMBEDDING_DIM = 16
LATENT_DIM = 8


def clean_minimal(query_text):
    if not isinstance(query_text, str): return ""
    query_text = unquote(query_text)

    query_text = query_text.replace("'", " ").replace('"', " ")

    query_text = re.sub(r'([^\w\s])', r' \1 ', query_text)

    return " ".join(query_text.split()).lower()


def train():
    if not os.path.exists(DATA_PATH):
        print("Error: Dataset not found.")
        return

    df = pd.read_csv(DATA_PATH)
    benign_df = df[df['label'] == 0].copy()
    attack_df = df[df['label'] == 1].copy()
    print(f"   Training on {len(benign_df)} benign samples.")

    benign_df['clean'] = benign_df['query'].apply(clean_minimal)
    attack_df['clean'] = attack_df['query'].apply(clean_minimal)

    X_train_text = benign_df['clean'].values
    X_attack_text = attack_df['clean'].values

    custom_filters = '!"#$%&()+,-./:;?@[\\]^`{|}~\t\n'

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token='<UNK>', filters=custom_filters)
    tokenizer.fit_on_texts(X_train_text)

    # Save Tokenizer
    with open('anomaly_tokenizer.pickle', 'wb') as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

    X_train_seq = tokenizer.texts_to_sequences(X_train_text)
    X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_LEN, padding='post', truncating='post')

    X_attack_seq = tokenizer.texts_to_sequences(X_attack_text)
    X_attack_pad = pad_sequences(X_attack_seq, maxlen=MAX_LEN, padding='post', truncating='post')

    inputs = Input(shape=(MAX_LEN,))
    embedding_layer = Embedding(VOCAB_SIZE, EMBEDDING_DIM, input_length=MAX_LEN, mask_zero=True)
    embedded = embedding_layer(inputs)

    encoded = Dropout(0.2)(embedded)
    encoded = LSTM(LATENT_DIM, activation='relu', return_sequences=False)(encoded)

    decoded = RepeatVector(MAX_LEN)(encoded)
    decoded = LSTM(EMBEDDING_DIM, activation='relu', return_sequences=True)(decoded)

    output = TimeDistributed(Dense(EMBEDDING_DIM, activation='linear'))(decoded)

    # Generator for Ground Truth Vectors
    vector_generator = Model(inputs, embedded)
    X_train_vectors = vector_generator.predict(X_train_pad, verbose=1)

    model = Model(inputs, output)
    model.compile(optimizer='adam', loss='mse')

    model.fit(X_train_pad, X_train_vectors, epochs=10, batch_size=64, validation_split=0.1, verbose=1)

    pred_vectors_benign = model.predict(X_train_pad)
    mse_benign = np.mean(np.square(X_train_vectors - pred_vectors_benign), axis=(1, 2))

    # Set Threshold
    threshold = np.percentile(mse_benign, 99)
    print(f"Calculated Threshold: {threshold:.6f}")

    model.save('anomaly_model.keras')
    with open('threshold.txt', 'w') as f:
        f.write(str(threshold))

if __name__ == "__main__":
    train()