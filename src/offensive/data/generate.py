import sys
import os

# Ensure imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.generator import generate_dataset

def generate_defender_dataset(filename="dataset.txt", count=100000):
    print(f"--- High-Speed Generation of {count} Attacks ---")
    
    # Use the fast generator (same one the model trained on)
    # It returns a list of (input, target) pairs
    # We only want the TARGET (the obfuscated attack) for the defender to detect
    raw_data = generate_dataset(count)
    
    print(f"Generated {len(raw_data)} samples in memory. Saving...")
    
    with open(filename, "w", encoding="utf-8") as f:
        for i, (src, trg) in enumerate(raw_data):
            f.write(trg + "\n")
            if i % 10000 == 0:
                print(f"Writing: {i}/{count}...", end='\r', flush=True)
            
    print(f"Done! Saved to {filename}")

if __name__ == "__main__":
    generate_defender_dataset()
