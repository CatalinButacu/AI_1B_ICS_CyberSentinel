from abc import ABC, abstractmethod

class BaseAttacker(ABC):
    """Abstract base class for Attack Agents."""
    
    @abstractmethod
    def mutate_payload(self, payload):
        """
        Input: Original payload string
        Output: Mutated payload string
        """
        pass
    
    @abstractmethod
    def attack(self, target_url):
        """Execute attack logic."""
        pass

class BaseDetector(ABC):
    """Abstract base class for ML Detectors."""
    
    @abstractmethod
    def extract_features(self, payload):
        """
        Input: Payload string
        Output: Numeric feature vector
        """
        pass
    
    @abstractmethod
    def predict(self, payload):
        """
        Input: Payload string
        Output: Probability score (0.0 - 1.0)
        """
        pass

class BaseFirewall(ABC):
    """Abstract base class for Smart Firewalls."""
    
    @abstractmethod
    def match_pattern(self, payload):
        """
        Input: Payload string
        Output: Boolean (True if matches known pattern)
        """
        pass
    
    @abstractmethod
    def update_rules(self, new_patterns):
        """
        Input: List of new patterns
        Output: None (Updates internal state)
        """
        pass
