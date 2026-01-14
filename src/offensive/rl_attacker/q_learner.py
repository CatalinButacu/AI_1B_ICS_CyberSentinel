"""
Q-Learning Agent for Candidate Selection
Learns which BiLSTM-generated mutations are most likely to bypass the firewall.
"""
import numpy as np
import pickle
import os

class QLearningSelector:
    """
    Q-Learning agent that selects the best mutation candidate.
    
    State Space: Simple features extracted from payload
    Action Space: Select candidate index (0-6 for 7 candidates by default)
    """
    
    def __init__(self, num_actions=7, learning_rate=0.1, discount_factor=0.95, 
                 epsilon=1.0, epsilon_decay=0.995, epsilon_min=0.01):
        """
        Initialize Q-Learning agent.
        
        Args:
            num_actions: Number of candidates to choose from (default 5)
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            epsilon: Initial exploration rate
            epsilon_decay: Epsilon decay rate per episode
            epsilon_min: Minimum epsilon value
        """
        self.num_actions = num_actions
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        
        # Q-table: state_hash -> [Q-values for each action]
        # We use a dictionary for sparse state representation
        self.q_table = {}
        
        # Statistics
        self.total_episodes = 0
        self.successful_bypasses = 0
    
    def get_state_hash(self, payload):
        """
        Convert payload to a state representation with richer features.
        
        Features:
        - Length bucket (0-20, 20-40, 40-60, 60+)
        - Has quotes (0/1)
        - Has comments (0/1)
        - Has keywords (0/1)
        - Has encoding (%20, %09, etc.) (0/1)
        - Has hex (0x...) (0/1)
        
        Returns:
            tuple: State hash for Q-table lookup
        """
        # Length bucket (more granular)
        if len(payload) < 20:
            length_bucket = 0
        elif len(payload) < 40:
            length_bucket = 1
        elif len(payload) < 60:
            length_bucket = 2
        else:
            length_bucket = 3
        
        # Feature flags
        has_quotes = 1 if "'" in payload or '"' in payload else 0
        has_comments = 1 if '--' in payload or '#' in payload or '/*' in payload else 0
        
        # SQL keywords (case insensitive)
        payload_lower = payload.lower()
        keywords = ['union', 'select', 'or', 'and', 'drop', 'insert']
        has_keywords = 1 if any(kw in payload_lower for kw in keywords) else 0
        
        # NEW: URL encoding detection
        has_encoding = 1 if '%' in payload else 0
        
        # NEW: Hex encoding detection
        has_hex = 1 if '0x' in payload_lower else 0
        
        return (length_bucket, has_quotes, has_comments, has_keywords, has_encoding, has_hex)
    
    def choose_action(self, state_hash):
        """
        Choose an action (candidate index) using epsilon-greedy policy.
        
        Args:
            state_hash: State representation
            
        Returns:
            int: Action index (0 to num_actions-1)
        """
        # Exploration: random action
        if np.random.rand() < self.epsilon:
            return np.random.randint(0, self.num_actions)
        
        # Exploitation: best known action
        if state_hash not in self.q_table:
            # Initialize Q-values for new state
            self.q_table[state_hash] = np.zeros(self.num_actions)
        
        return np.argmax(self.q_table[state_hash])
    
    def learn(self, state_hash, action, reward, next_state_hash, done):
        """
        Update Q-table using Q-Learning update rule.
        
        Q(s,a) = Q(s,a) + α * [reward + γ * max(Q(s',a')) - Q(s,a)]
        
        Args:
            state_hash: Current state
            action: Action taken
            reward: Reward received
            next_state_hash: Next state
            done: Whether episode is done
        """
        # Initialize Q-values if needed
        if state_hash not in self.q_table:
            self.q_table[state_hash] = np.zeros(self.num_actions)
        if next_state_hash not in self.q_table:
            self.q_table[next_state_hash] = np.zeros(self.num_actions)
        
        # Q-Learning update
        current_q = self.q_table[state_hash][action]
        
        if done:
            # Terminal state: no future reward
            target_q = reward
        else:
            # Non-terminal: include discounted future reward
            max_next_q = np.max(self.q_table[next_state_hash])
            target_q = reward + self.gamma * max_next_q
        
        # Update Q-value
        self.q_table[state_hash][action] += self.lr * (target_q - current_q)
        
        # Decay epsilon after each episode
        if done:
            self.total_episodes += 1
            if self.epsilon > self.epsilon_min:
                self.epsilon *= self.epsilon_decay
            
            if reward > 0:  # Successful bypass
                self.successful_bypasses += 1
    
    def get_success_rate(self):
        """Calculate overall success rate."""
        if self.total_episodes == 0:
            return 0.0
        return (self.successful_bypasses / self.total_episodes) * 100
    
    def save(self, filepath='q_table_hybrid.pkl'):
        """Save Q-table and statistics to disk."""
        # Handle relative path - save in current directory
        import os
        if not os.path.isabs(filepath):
            # If running from rl_attacker/, save there
            # If running from root, save in rl_attacker/
            if os.path.basename(os.getcwd()) == 'rl_attacker':
                filepath = filepath
            else:
                filepath = os.path.join('rl_attacker', filepath)
        
        data = {
            'q_table': self.q_table,
            'epsilon': self.epsilon,
            'total_episodes': self.total_episodes,
            'successful_bypasses': self.successful_bypasses
        }
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        print(f"Q-table saved to {filepath}")
    
    def load(self, filepath='q_table_hybrid.pkl'):
        """Load Q-table and statistics from disk."""
        # Handle relative path
        import os
        if not os.path.isabs(filepath):
            if os.path.basename(os.getcwd()) == 'rl_attacker':
                filepath = filepath
            else:
                filepath = os.path.join('rl_attacker', filepath)
        
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            self.q_table = data['q_table']
            self.epsilon = data['epsilon']
            self.total_episodes = data['total_episodes']
            self.successful_bypasses = data['successful_bypasses']
            print(f"Q-table loaded from {filepath}")
            print(f"Episodes: {self.total_episodes}, Success Rate: {self.get_success_rate():.2f}%")
            return True
        return False


if __name__ == "__main__":
    # Test the Q-Learning selector
    selector = QLearningSelector(num_actions=5)
    
    # Simulate some learning
    test_payload = "' OR 1=1 --"
    state = selector.get_state_hash(test_payload)
    
    print(f"State hash for '{test_payload}': {state}")
    print(f"Initial Q-values: {selector.q_table.get(state, 'Not initialized')}")
    
    # Simulate choosing actions and learning
    for episode in range(10):
        action = selector.choose_action(state)
        reward = 10 if np.random.rand() > 0.5 else -1  # Random reward
        next_state = state  # Same state for simplicity
        selector.learn(state, action, reward, next_state, done=True)
    
    print(f"\nAfter 10 episodes:")
    print(f"Q-values: {selector.q_table[state]}")
    print(f"Best action: {np.argmax(selector.q_table[state])}")
    print(f"Epsilon: {selector.epsilon:.3f}")
