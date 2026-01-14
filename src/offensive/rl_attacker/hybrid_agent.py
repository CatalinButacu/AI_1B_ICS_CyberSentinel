"""
Hybrid RL-BiLSTM Attack Agent
Combines BiLSTM generation with Q-Learning selection for adaptive SQL injection attacks.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import time
from rl_attacker.bilstm_wrapper import BiLSTMGenerator
from rl_attacker.q_learner import QLearningSelector
from data.generator import BASE_PAYLOADS

class HybridAttackAgent:
    """
    Hybrid agent that combines:
    1. BiLSTM for generating diverse mutation candidates
    2. Q-Learning for selecting the best candidate
    3. Firewall interaction for testing and learning
    """
    
    def __init__(self, firewall_url="http://localhost:5000/login", num_candidates=7):
        """
        Initialize the hybrid agent.
        
        Args:
            firewall_url: URL of the target endpoint (default: dummy_target.py)
            num_candidates: Number of candidates to generate per attack (default: 7)
        """
        self.firewall_url = firewall_url
        self.num_candidates = num_candidates
        
        # Initialize components
        print("Initializing Hybrid RL-BiLSTM Agent...")
        self.generator = BiLSTMGenerator()
        self.selector = QLearningSelector(num_actions=num_candidates)
        
        # Statistics
        self.attack_history = []
        self.bypass_count = 0
        self.blocked_count = 0
        
        # Best model tracking
        self.best_success_rate = 0.0
        self.best_q_table = None
        self.best_episode = 0
    
    def send_to_firewall(self, payload, timeout=2):
        """
        Send payload to target and get response.
        
        Args:
            payload: SQL injection payload to test
            timeout: Request timeout in seconds
            
        Returns:
            tuple: (bypassed: bool, status_code: int, response_data: dict)
        """
        try:
            # Send as GET request with 'q' parameter (dummy_target.py format)
            response = requests.get(
                self.firewall_url,
                params={"q": payload},
                timeout=timeout
            )
            
            # dummy_target.py returns:
            # - 403: Blocked by WAF
            # - 200: Bypassed WAF (success)
            # - 401: Login failed (but bypassed WAF)
            bypassed = response.status_code in [200, 401, 500]
            
            return bypassed, response.status_code, {"text": response.text[:100]}
            
        except requests.exceptions.Timeout:
            print(f"Timeout connecting to firewall at {self.firewall_url}")
            return False, 0, {"error": "timeout"}
        except requests.exceptions.ConnectionError:
            print(f"Connection error: Is firewall running at {self.firewall_url}?")
            return False, 0, {"error": "connection_error"}
        except Exception as e:
            print(f"Error sending payload: {e}")
            return False, 0, {"error": str(e)}
    
    def attack_single(self, base_payload, learn=True):
        """
        Execute a single attack with learning.
        
        Args:
            base_payload: Base SQL injection payload
            learn: Whether to update Q-table (False for testing)
            
        Returns:
            dict: Attack result with statistics
        """
        # Step 1: Generate candidates using BiLSTM
        candidates = self.generator.generate_candidates(base_payload, self.num_candidates)
        
        # Step 2: Get state representation
        state_hash = self.selector.get_state_hash(base_payload)
        
        # Step 3: Select candidate using Q-Learning
        action = self.selector.choose_action(state_hash)
        selected_payload = candidates[action]
        
        # Step 4: Send to firewall
        bypassed, status_code, response_data = self.send_to_firewall(selected_payload)
        
        # Step 5: Calculate reward
        if bypassed:
            reward = 10  # Big reward for successful bypass
            self.bypass_count += 1
        else:
            reward = -1  # Small penalty for being blocked
            self.blocked_count += 1
        
        # Step 6: Learn from result
        if learn:
            next_state_hash = self.selector.get_state_hash(selected_payload)
            self.selector.learn(state_hash, action, reward, next_state_hash, done=True)
        
        # Step 7: Record statistics
        result = {
            'base_payload': base_payload,
            'candidates': candidates,
            'selected_index': action,
            'selected_payload': selected_payload,
            'bypassed': bypassed,
            'reward': reward,
            'status_code': status_code,
            'epsilon': self.selector.epsilon
        }
        
        self.attack_history.append(result)
        
        return result
    
    def train(self, episodes=100, base_payloads=None):
        """
        Train the agent against the firewall.
        
        Args:
            episodes: Number of training episodes
            base_payloads: List of base payloads to use (default: BASE_PAYLOADS)
        """
        if base_payloads is None:
            base_payloads = BASE_PAYLOADS[:20]  # Use subset for faster training
        
        print(f"\n{'='*60}")
        print(f"Starting Hybrid RL-BiLSTM Training")
        print(f"Episodes: {episodes}")
        print(f"Base Payloads: {len(base_payloads)}")
        print(f"Firewall: {self.firewall_url}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        for episode in range(episodes):
            # Select random base payload
            import random
            base_payload = random.choice(base_payloads)
            
            # Execute attack
            result = self.attack_single(base_payload, learn=True)
            
            # Track best performance (check every 50 episodes for stability)
            if (episode + 1) % 50 == 0:
                current_success_rate = (self.bypass_count / (episode + 1)) * 100
                if current_success_rate > self.best_success_rate:
                    self.best_success_rate = current_success_rate
                    self.best_episode = episode + 1
                    # Deep copy the Q-table
                    import copy
                    self.best_q_table = copy.deepcopy(self.selector.q_table)
                    print(f"  ⭐ New best: {current_success_rate:.1f}% at episode {episode + 1}")
            
            # Print progress every 10 episodes
            if (episode + 1) % 10 == 0:
                success_rate = (self.bypass_count / (episode + 1)) * 100
                print(f"Episode {episode + 1}/{episodes} | "
                      f"Success Rate: {success_rate:.1f}% | "
                      f"Epsilon: {result['epsilon']:.3f} | "
                      f"Last: {'✓ BYPASS' if result['bypassed'] else '✗ BLOCKED'}")
        
        duration = time.time() - start_time
        
        # Final statistics
        print(f"\n{'='*60}")
        print(f"Training Complete!")
        print(f"{'='*60}")
        print(f"Total Episodes: {episodes}")
        print(f"Bypassed: {self.bypass_count} ({(self.bypass_count/episodes)*100:.1f}%)")
        print(f"Blocked: {self.blocked_count} ({(self.blocked_count/episodes)*100:.1f}%)")
        print(f"Training Time: {duration:.2f}s")
        print(f"Final Epsilon: {self.selector.epsilon:.3f}")
        if self.best_q_table is not None:
            print(f"\n⭐ Best Performance: {self.best_success_rate:.1f}% at episode {self.best_episode}")
        print(f"{'='*60}\n")
    
    def test(self, test_payloads=None, num_tests=50):
        """
        Test the trained agent (no learning).
        
        Args:
            test_payloads: List of payloads to test (default: BASE_PAYLOADS)
            num_tests: Number of tests to run
        """
        if test_payloads is None:
            test_payloads = BASE_PAYLOADS
        
        print(f"\n{'='*60}")
        print(f"Testing Hybrid Agent (No Learning)")
        print(f"{'='*60}\n")
        
        test_bypass = 0
        test_blocked = 0
        
        import random
        for i in range(num_tests):
            base_payload = random.choice(test_payloads)
            result = self.attack_single(base_payload, learn=False)
            
            if result['bypassed']:
                test_bypass += 1
            else:
                test_blocked += 1
            
            if (i + 1) % 10 == 0:
                print(f"Test {i + 1}/{num_tests} | Success Rate: {(test_bypass/(i+1))*100:.1f}%")
        
        print(f"\n{'='*60}")
        print(f"Test Results:")
        print(f"Bypassed: {test_bypass}/{num_tests} ({(test_bypass/num_tests)*100:.1f}%)")
        print(f"Blocked: {test_blocked}/{num_tests} ({(test_blocked/num_tests)*100:.1f}%)")
        print(f"{'='*60}\n")
    
    def save(self, save_best=True):
        """
        Save the Q-table(s).
        
        Args:
            save_best: If True, also save the best Q-table separately
        """
        # Save final Q-table
        self.selector.save('q_table_hybrid.pkl')
        
        # Save best Q-table if available
        if save_best and self.best_q_table is not None:
            import pickle
            data = {
                'q_table': self.best_q_table,
                'epsilon': self.selector.epsilon,
                'best_episode': self.best_episode,
                'best_success_rate': self.best_success_rate
            }
            with open('q_table_hybrid_best.pkl', 'wb') as f:
                pickle.dump(data, f)
            print(f"✓ Best Q-table saved to q_table_hybrid_best.pkl (Episode {self.best_episode}, {self.best_success_rate:.1f}%)")
    
    def load(self, use_best=False):
        """
        Load the Q-table.
        
        Args:
            use_best: If True, load the best Q-table instead of final
        """
        if use_best:
            import pickle
            import os
            filepath = 'q_table_hybrid_best.pkl'
            if os.path.basename(os.getcwd()) != 'rl_attacker':
                filepath = os.path.join('rl_attacker', filepath)
            
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    data = pickle.load(f)
                self.selector.q_table = data['q_table']
                self.selector.epsilon = data.get('epsilon', 0.01)
                print(f"✓ Best Q-table loaded from {filepath}")
                print(f"  Episode: {data.get('best_episode', 'unknown')}, Success Rate: {data.get('best_success_rate', 0):.1f}%")
                return True
            else:
                print(f"⚠ Best Q-table not found, loading final Q-table instead")
                return self.selector.load()
        else:
            return self.selector.load()
    
    def get_statistics(self):
        """Get detailed statistics."""
        total_attacks = len(self.attack_history)
        if total_attacks == 0:
            return {"error": "No attacks executed yet"}
        
        return {
            'total_attacks': total_attacks,
            'bypassed': self.bypass_count,
            'blocked': self.blocked_count,
            'bypass_rate': (self.bypass_count / total_attacks) * 100,
            'q_table_size': len(self.selector.q_table),
            'epsilon': self.selector.epsilon
        }


if __name__ == "__main__":
    # Demo usage
    agent = HybridAttackAgent()
    
    # Try to load existing Q-table
    agent.load()
    
    # Train for 100 episodes
    agent.train(episodes=100)
    
    # Save learned Q-table
    agent.save()
    
    # Test the agent
    agent.test(num_tests=50)
    
    # Print final statistics
    stats = agent.get_statistics()
    print("\nFinal Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
