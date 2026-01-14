import torch
import torch.nn as nn
import math

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super(PositionalEncoding, self).__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(1) # Shape: (max_len, 1, d_model)
        self.register_buffer('pe', pe)

    def forward(self, x):
        return x + self.pe[:x.size(0), :]

class TransformerModel(nn.Module):
    def __init__(self, input_dim, output_dim, d_model, nhead, num_encoder_layers, num_decoder_layers, dim_feedforward, dropout):
        super(TransformerModel, self).__init__()
        self.d_model = d_model
        
        self.embedding = nn.Embedding(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        
        self.transformer = nn.Transformer(
            d_model=d_model,
            nhead=nhead,
            num_encoder_layers=num_encoder_layers,
            num_decoder_layers=num_decoder_layers,
            dim_feedforward=dim_feedforward,
            dropout=dropout
        )
        
        self.fc_out = nn.Linear(d_model, output_dim)
        
    def forward(self, src, trg):
        # src: [src_len, batch_size]
        # trg: [trg_len, batch_size]
        
        src = self.pos_encoder(self.embedding(src) * math.sqrt(self.d_model))
        trg = self.pos_encoder(self.embedding(trg) * math.sqrt(self.d_model))
        
        # We need a target mask to prevent looking ahead
        trg_mask = self.transformer.generate_square_subsequent_mask(trg.size(0)).to(trg.device)
        
        output = self.transformer(src, trg, tgt_mask=trg_mask)
        return self.fc_out(output)
