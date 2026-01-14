import torch
import torch.nn as nn
import torch.optim as optim
from .model import TransformerModel
from bilstm_sqli.model import Vocab # Reuse Vocab class
from data.generator import generate_dataset
import random

def train():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # 1. Generate Data (Scaled up for Transformer)
    # Transformers need more data to generalize than LSTMs
    print("Generating 50,000 synthetic training examples... (This is 'getting more data')")
    raw_data = generate_dataset(50000)
    vocab = Vocab()
    vocab.build_vocab(raw_data)
    
    print(f"Vocab Size: {vocab.n_words}")
    
    # 2. Config Transformer
    INPUT_DIM = vocab.n_words
    OUTPUT_DIM = vocab.n_words
    D_MODEL = 64
    NHEAD = 4
    NUM_ENC_LAYERS = 2
    NUM_DEC_LAYERS = 2
    DIM_FEEDFORWARD = 128
    DROPOUT = 0.1

    model = TransformerModel(INPUT_DIM, OUTPUT_DIM, D_MODEL, NHEAD, NUM_ENC_LAYERS, NUM_DEC_LAYERS, DIM_FEEDFORWARD, DROPOUT).to(device)
    
    optimizer = optim.Adam(model.parameters(), lr=0.0005)
    criterion = nn.CrossEntropyLoss(ignore_index=vocab.stoi['<pad>'])
    
    # 3. Training Loop
    model.train()
    print("Starting Transformer Training...")
    loss_history = []
    
    for epoch in range(10): 
        epoch_loss = 0
        random.shuffle(raw_data)
        
        for i, (src_txt, trg_txt) in enumerate(raw_data):
            # Tensorize
            src = torch.tensor([vocab.stoi['<sos>']] + vocab.encode(src_txt) + [vocab.stoi['<eos>']], device=device).unsqueeze(1)
            trg = torch.tensor([vocab.stoi['<sos>']] + vocab.encode(trg_txt) + [vocab.stoi['<eos>']], device=device).unsqueeze(1)
            
            # Transformer expects target input (shifted) for teacher forcing
            trg_input = trg[:-1, :]
            trg_output = trg[1:, :]
            
            optimizer.zero_grad()
            output = model(src, trg_input)
            
            # Reshape for loss
            output_dim = output.shape[-1]
            output = output.view(-1, output_dim)
            trg_output = trg_output.view(-1)
            
            loss = criterion(output, trg_output)
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            
        avg_loss = epoch_loss / len(raw_data)
        loss_history.append(avg_loss)
        print(f"Epoch: {epoch+1}, Loss: {avg_loss:.4f}")

    # 4. Save
    torch.save(model.state_dict(), 'transformer_sqli/transformer_model.pt')
    import pickle
    with open('transformer_sqli/vocab_transformer.pkl', 'wb') as f:
        pickle.dump(vocab, f)
    print("Transformer Model Saved.")
    
    # Save Loss History for Visualization
    import pickle
    with open('benchmark/transformer_loss.pkl', 'wb') as f:
        pickle.dump(loss_history, f)
    print("Loss history saved to benchmark/transformer_loss.pkl")

if __name__ == "__main__":
    train()
