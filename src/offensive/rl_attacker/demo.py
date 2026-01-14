"""
Quick Demo of Hybrid RL-BiLSTM Agent
Shows how the system works without needing the firewall running.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bilstm_wrapper import BiLSTMGenerator
from q_learner import QLearningSelector

def demo_bilstm_generation():
    """Demonstrate BiLSTM candidate generation."""
    print("="*60)
    print("DEMO 1: BiLSTM Candidate Generation")
    print("="*60)
    
    generator = BiLSTMGenerator()
    
    test_payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT 1,2,3 --"
    ]
    
    for payload in test_payloads:
        print(f"\n📝 Base Payload: {payload}")
        print("   BiLSTM generates 5 candidates:")
        
        candidates = generator.generate_candidates(payload, num_candidates=5)
        for i, candidate in enumerate(candidates):
            print(f"   [{i}] {candidate}")

def demo_q_learning():
    """Demonstrate Q-Learning selection."""
    print("\n" + "="*60)
    print("DEMO 2: Q-Learning Selection")
    print("="*60)
    
    selector = QLearningSelector(num_actions=5)
    
    # Simulate learning
    test_payload = "' OR 1=1 --"
    state = selector.get_state_hash(test_payload)
    
    print(f"\n📝 Payload: {test_payload}")
    print(f"   State Hash: {state}")
    print(f"   (length_bucket, has_quotes, has_comments, has_keywords)")
    
    print("\n🎓 Simulating 20 learning episodes...")
    for episode in range(20):
        action = selector.choose_action(state)
        # Simulate: actions 1 and 3 work better
        if action in [1, 3]:
            reward = 10  # Success
        else:
            reward = -1  # Failure
        
        selector.learn(state, action, reward, state, done=True)
    
    print(f"\n📊 Learned Q-values:")
    print(f"   {selector.q_table[state]}")
    print(f"\n✓ Best action: {selector.q_table[state].argmax()} (highest Q-value)")
    print(f"   This means candidate [{selector.q_table[state].argmax()}] works best!")

def demo_hybrid_workflow():
    """Demonstrate the full hybrid workflow."""
    print("\n" + "="*60)
    print("DEMO 3: Hybrid Workflow (Without Firewall)")
    print("="*60)
    
    generator = BiLSTMGenerator()
    selector = QLearningSelector(num_actions=5)
    
    base_payload = "' UNION SELECT password FROM users --"
    
    print(f"\n📝 Base Payload: {base_payload}")
    
    # Step 1: Generate candidates
    print("\n🔧 Step 1: BiLSTM generates 5 candidates...")
    candidates = generator.generate_candidates(base_payload, num_candidates=5)
    for i, candidate in enumerate(candidates):
        print(f"   [{i}] {candidate}")
    
    # Step 2: Get state
    print("\n🔍 Step 2: Extract state features...")
    state = selector.get_state_hash(base_payload)
    print(f"   State: {state}")
    
    # Step 3: Select action
    print("\n🎯 Step 3: Q-Learning selects best candidate...")
    action = selector.choose_action(state)
    selected = candidates[action]
    print(f"   Selected: [{action}] {selected}")
    
    # Step 4: Simulate firewall response
    print("\n🔥 Step 4: Send to firewall (simulated)...")
    import random
    bypassed = random.choice([True, False])
    reward = 10 if bypassed else -1
    print(f"   Result: {'✓ BYPASSED' if bypassed else '✗ BLOCKED'}")
    print(f"   Reward: {reward}")
    
    # Step 5: Learn
    print("\n🎓 Step 5: Update Q-table...")
    selector.learn(state, action, reward, state, done=True)
    print(f"   Q-value for action {action}: {selector.q_table[state][action]:.2f}")
    
    print("\n✓ Hybrid workflow complete!")

def main():
    print("\n" + "🚀 "*20)
    print("Hybrid RL-BiLSTM Agent Demo")
    print("🚀 "*20 + "\n")
    
    try:
        # Demo 1: BiLSTM Generation
        demo_bilstm_generation()
        
        # Demo 2: Q-Learning
        demo_q_learning()
        
        # Demo 3: Full Workflow
        demo_hybrid_workflow()
        
        print("\n" + "="*60)
        print("✓ All demos complete!")
        print("="*60)
        print("\nNext steps:")
        print("1. Make sure firewall is running: python src/firewall/firewall.py")
        print("2. Train the agent: python rl_attacker/train_hybrid.py")
        print("3. Test the agent: python rl_attacker/train_hybrid.py --test-only")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure BiLSTM model is trained first:")
        print("  python -m bilstm_sqli.train")

if __name__ == "__main__":
    main()
