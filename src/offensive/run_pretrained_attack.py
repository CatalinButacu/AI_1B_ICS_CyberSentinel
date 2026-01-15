import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from shared.config import FIREWALL_URL, WEBAPP_URL, ENVIRONMENT

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'rl_attacker'))
from rl_attacker.hybrid_agent import HybridAttackAgent
from data.generator import BASE_PAYLOADS

def run_pretrained_attack():
    print("=" * 60)
    print("  RADU'S HYBRID RL-BiLSTM ATTACK AGENT")
    print("  Using Pre-trained Model (no training)")
    print("=" * 60)
    print(f"[ENV] {ENVIRONMENT}")
    print(f"[TARGET] {FIREWALL_URL}/filter")
    print("")
    
    agent = HybridAttackAgent(firewall_url=f"{FIREWALL_URL}/filter")
    
    # Load pre-trained Q-table
    q_table_path = os.path.join(os.path.dirname(__file__), 'rl_attacker', 'q_table_hybrid_best.pkl')
    if os.path.exists(q_table_path):
        agent.load_q_table(q_table_path)
        print(f"[LOADED] Pre-trained Q-table from: q_table_hybrid_best.pkl")
    else:
        print(f"[WARN] Pre-trained Q-table not found, using fresh agent")
    
    print("")
    print("Starting attacks using pre-trained model...")
    print("-" * 60)
    
    # Run attacks with learn=False (no training, just use pre-trained)
    success_count = 0
    total_count = 0
    
    for payload in BASE_PAYLOADS[:10]:
        total_count += 1
        try:
            result = agent.attack_single(payload, learn=False)
            
            if result.get('bypassed'):
                success_count += 1
                print(f"[✓ BYPASS] {result['selected_payload'][:50]}...")
            else:
                print(f"[✗ BLOCKED] {result['selected_payload'][:50]}...")
                
        except Exception as e:
            print(f"[ERROR] {e}")
    
    print("-" * 60)
    print(f"Results: {success_count}/{total_count} bypassed ({(success_count/total_count)*100:.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    run_pretrained_attack()
