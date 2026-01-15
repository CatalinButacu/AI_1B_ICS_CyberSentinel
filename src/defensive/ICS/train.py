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
from sklearn.metrics import recall_score, accuracy_score, precision_score, confusion_matrix

vocab_size = 10000
max_length = 100
dim = 32


def train():

    df = pd.read_csv('labeled_dataset.csv')

    X = df['query'].astype(str)
    y = df['label'].values

    # Tokenizer - Character level=False to capture words like 'SELECT' or 'UNION'
    tokenizer = Tokenizer(num_words=vocab_size, char_level=False, lower=True)
    tokenizer.fit_on_texts(X)

    #Save tokenizer
    with open('tokenizer.pickle', 'wb') as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

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
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy:  {acc:.4f}")
    prec = precision_score(y_test, y_pred, average='binary')
    print(f"Precision: {prec:.4f}")
    print(f"Recall:  {recall:.4f}.")

    model.save('my_model.keras')

if __name__ == "__main__":
    train()