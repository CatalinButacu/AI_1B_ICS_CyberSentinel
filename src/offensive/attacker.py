"""
SQL Injection Attack Agent using Hybrid RL-BiLSTM
Author: Radu (Offensive Team)

This module integrates the DeepSQLi-RL hybrid approach with the team's architecture.
Uses BiLSTM for mutation generation and Q-Learning for adaptive selection.
"""
import sys
import os

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'rl_attacker'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

from rl_attacker.hybrid_agent import HybridAttackAgent
from data.generator import BASE_PAYLOADS

# Try to import team's shared config, fallback to defaults
try:
    from config import FIREWALL_URL, API_TIMEOUT
    ATTACK_TARGET = FIREWALL_URL + "/filter"
except ImportError:
    ATTACK_TARGET = "http://localhost:5001/filter"
    API_TIMEOUT = 5

# Try to import team's interface, fallback to basic implementation
try:
    from interfaces import BaseAttacker
    
    class HybridAttacker(BaseAttacker):
        """Team-compatible wrapper for Hybrid RL-BiLSTM agent."""
        
        def __init__(self, target_url=None):
            self.target_url = target_url or ATTACK_TARGET
            self.agent = HybridAttackAgent(firewall_url=self.target_url)
            
        def mutate_payload(self, payload):
            """Generate mutation using hybrid approach."""
            # Generate candidates and select best
            result = self.agent.attack_single(payload, learn=True)
            return result['selected_payload']
        
        def attack(self, target_url):
            """Implementation of BaseAttacker interface."""
            self.target_url = target_url
            self.agent.firewall_url = target_url
            return self.run_attack_training()
        
        def run_attack_training(self, num_episodes=100):
            """Train the hybrid agent."""
            print(f"Starting Hybrid RL-BiLSTM training: {num_episodes} episodes")
            print(f"Target: {self.target_url}")
            
            self.agent.train(episodes=num_episodes, base_payloads=BASE_PAYLOADS)
            
            return self.agent.get_statistics()
        
        def print_attack_summary(self):
            """Print attack statistics."""
            stats = self.agent.get_statistics()
            print("\n" + "="*60)
            print("HYBRID RL-BiLSTM ATTACK SUMMARY")
            print("="*60)
            print(f"Total attacks:       {stats['total_attacks']}")
            print(f"Bypassed:            {stats['bypassed']}")
            print(f"Blocked:             {stats['blocked']}")
            print(f"Bypass rate:         {stats['bypass_rate']:.1f}%")
            print(f"Q-table size:        {stats['q_table_size']}")
            print("="*60)

except ImportError:
    # Fallback if team's shared module doesn't exist
    class HybridAttacker:
        """Standalone wrapper for Hybrid RL-BiLSTM agent."""
        
        def __init__(self, target_url=None):
            self.target_url = target_url or ATTACK_TARGET
            self.agent = HybridAttackAgent(firewall_url=self.target_url)
        
        def run_attack_training(self, num_episodes=100):
            """Train the hybrid agent."""
            print(f"Starting Hybrid RL-BiLSTM training: {num_episodes} episodes")
            print(f"Target: {self.target_url}")
            
            self.agent.train(episodes=num_episodes, base_payloads=BASE_PAYLOADS)
            
            return self.agent.get_statistics()
        
        def print_attack_summary(self):
            """Print attack statistics."""
            stats = self.agent.get_statistics()
            print("\n" + "="*60)
            print("HYBRID RL-BiLSTM ATTACK SUMMARY")
            print("="*60)
            print(f"Total attacks:       {stats['total_attacks']}")
            print(f"Bypassed:            {stats['bypassed']}")
            print(f"Blocked:             {stats['blocked']}")
            print(f"Bypass rate:         {stats['bypass_rate']:.1f}%")
            print(f"Q-table size:        {stats['q_table_size']}")
            print("="*60)


def main():
    print("="*60)
    print("HYBRID RL-BiLSTM ATTACK AGENT")
    print("DeepSQLi-RL: BiLSTM Generation + Q-Learning Selection")
    print("="*60 + "\n")
    
    agent = HybridAttacker()
    
    try:
        agent.run_attack_training(num_episodes=50)
        agent.print_attack_summary()
    except KeyboardInterrupt:
        print("\nTraining stopped.")
        agent.print_attack_summary()


if __name__ == "__main__":
    main()
