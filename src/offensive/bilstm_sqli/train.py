import torch
import torch.nn as nn
import torch.optim as optim
from .model import Encoder, Decoder, Seq2Seq, Vocab
from data.generator import generate_dataset
import random
import numpy as np

def train():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # 1. Generate Data (Aggressive & Quick)
    print("Generating 10,000 aggressive training examples...")
    raw_data = generate_dataset(10000)
    vocab = Vocab()
    vocab.build_vocab(raw_data)
    
    print(f"Vocab Size: {vocab.n_words}")
    
    # 2. Initialize Model
    INPUT_DIM = vocab.n_words
    OUTPUT_DIM = vocab.n_words
    ENC_EMB_DIM = 32
    DEC_EMB_DIM = 32
    HID_DIM = 64
    N_LAYERS = 1
    ENC_DROPOUT = 0.5
    DEC_DROPOUT = 0.5

    enc = Encoder(INPUT_DIM, ENC_EMB_DIM, HID_DIM, N_LAYERS, ENC_DROPOUT)
    dec = Decoder(OUTPUT_DIM, DEC_EMB_DIM, HID_DIM, N_LAYERS, DEC_DROPOUT)
    model = Seq2Seq(enc, dec, device).to(device)
    
    optimizer = optim.Adam(model.parameters())
    criterion = nn.CrossEntropyLoss(ignore_index=vocab.stoi['<pad>'])
    
    # 3. Training Loop
    model.train()
    print("Starting DeepSQLi Training...")
    loss_history = []
    
    for epoch in range(10): # Quick training
        epoch_loss = 0
        random.shuffle(raw_data)
        
        for i, (src_txt, trg_txt) in enumerate(raw_data):
            # Tensorize
            src = torch.tensor([vocab.stoi['<sos>']] + vocab.encode(src_txt) + [vocab.stoi['<eos>']], device=device).unsqueeze(1)
            trg = torch.tensor([vocab.stoi['<sos>']] + vocab.encode(trg_txt) + [vocab.stoi['<eos>']], device=device).unsqueeze(1)
            
            optimizer.zero_grad()
            output = model(src, trg)
            
            # output = [trg len, batch size, output dim]
            # trg = [trg len, batch size]
            
            output_dim = output.shape[-1]
            output = output[1:].view(-1, output_dim)
            trg = trg[1:].view(-1)
            
            loss = criterion(output, trg)
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            
        avg_loss = epoch_loss / len(raw_data)
        loss_history.append(avg_loss)
        print(f"Epoch: {epoch+1}, Loss: {avg_loss:.4f}")

    # 4. Save
    torch.save(model.state_dict(), 'bilstm_sqli/bilstm_model.pt')
    import pickle
    with open('bilstm_sqli/vocab.pkl', 'wb') as f:
        pickle.dump(vocab, f)
    print("Model Saved.")
    
    # Save Loss History for Visualization
    import pickle
    with open('benchmark/bilstm_loss.pkl', 'wb') as f:
        pickle.dump(loss_history, f)
    print("Loss history saved to benchmark/bilstm_loss.pkl")

if __name__ == "__main__":
    train()
