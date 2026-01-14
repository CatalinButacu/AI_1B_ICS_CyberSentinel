"""
Training Script for Hybrid RL-BiLSTM Agent
Run this to train the agent against the firewall.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hybrid_agent import HybridAttackAgent
from data.generator import BASE_PAYLOADS
import argparse

def main():
    parser = argparse.ArgumentParser(description='Train Hybrid RL-BiLSTM Attack Agent')
    parser.add_argument('--episodes', type=int, default=200, 
                       help='Number of training episodes (default: 200)')
    parser.add_argument('--firewall-url', type=str, default='http://localhost:5000/login',
                       help='Target endpoint (default: http://localhost:5000/login for dummy_target.py)')
    parser.add_argument('--test', action='store_true',
                       help='Run testing after training')
    parser.add_argument('--test-only', action='store_true',
                       help='Only run testing (load existing Q-table)')
    parser.add_argument('--num-candidates', type=int, default=7,
                       help='Number of candidates to generate per attack (default: 7)')
    parser.add_argument('--use-best', action='store_true',
                       help='Load and use the best Q-table instead of final')
    
    args = parser.parse_args()
    
    # Initialize agent
    print("Initializing Hybrid RL-BiLSTM Agent...")
    agent = HybridAttackAgent(
        firewall_url=args.firewall_url,
        num_candidates=args.num_candidates
    )
    
    # Load existing Q-table if available
    if args.test_only:
        print("\nTest-only mode: Loading existing Q-table...")
        if not agent.load(use_best=args.use_best):
            print("Error: No saved Q-table found. Train the agent first.")
            return
    else:
        # Try to load for continued training
        agent.load(use_best=args.use_best)
    
    # Training phase
    if not args.test_only:
        print("\n" + "="*60)
        print("TRAINING PHASE")
        print("="*60)
        agent.train(episodes=args.episodes, base_payloads=BASE_PAYLOADS)
        
        # Save the trained Q-table
        agent.save()
    
    # Testing phase
    if args.test or args.test_only:
        print("\n" + "="*60)
        print("TESTING PHASE")
        print("="*60)
        agent.test(test_payloads=BASE_PAYLOADS, num_tests=100)
    
    # Print final statistics
    print("\n" + "="*60)
    print("FINAL STATISTICS")
    print("="*60)
    stats = agent.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"{key:20s}: {value:.2f}")
        else:
            print(f"{key:20s}: {value}")
    
    print("\n✓ Training complete! Q-table saved to rl_attacker/q_table_hybrid.pkl")


if __name__ == "__main__":
    main()
