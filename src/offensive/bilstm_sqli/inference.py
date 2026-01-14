import torch
from .model import Encoder, Decoder, Seq2Seq, Vocab
import pickle

def load_model(vocab_path='bilstm_sqli/vocab.pkl', model_path='bilstm_sqli/bilstm_model.pt'):
    # Load Vocab
    with open(vocab_path, 'rb') as f:
        vocab = pickle.load(f)
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # Re-init Model (Must match training params)
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
    
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    
    return model, vocab, device

def translate_sentence(sentence, model, vocab, device, max_len=50):
    model.eval()
    tokens = [vocab.stoi.get(c, vocab.stoi['<unk>']) for c in sentence]
    src_tensor = torch.LongTensor([vocab.stoi['<sos>']] + tokens + [vocab.stoi['<eos>']]).unsqueeze(1).to(device)
    
    with torch.no_grad():
        hidden, cell = model.encoder(src_tensor)
    
    trg_indexes = [vocab.stoi['<sos>']]
    
    for i in range(max_len):
        trg_tensor = torch.LongTensor([trg_indexes[-1]]).to(device)
        with torch.no_grad():
            output, hidden, cell = model.decoder(trg_tensor, hidden, cell)
        pred_token = output.argmax(1).item()
        trg_indexes.append(pred_token)
        if pred_token == vocab.stoi['<eos>']:
            break
            
    trg_tokens = [vocab.itos[i] for i in trg_indexes]
    return "".join(trg_tokens[1:-1]) # Skip SOS and EOS

if __name__ == "__main__":
    model, vocab, device = load_model()
    
    test_attacks = [
        "' OR 1=1 --",
        "admin' --",
        "1 UNION SELECT 1,2"
    ]
    
    print("--- DeepSQLi Attack Generator ---")
    for attack in test_attacks:
        generated = translate_sentence(attack, model, vocab, device)
        print(f"Input:  {attack}")
        print(f"Output: {generated}")
        print("-" * 20)
