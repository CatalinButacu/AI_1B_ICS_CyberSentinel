"""
Attack Pattern Extractor using DBSCAN Clustering
Author: Catalin (Firewall Team)

TODO: Add Isolation Forest for network anomaly detection
TODO: Implement incremental clustering for real-time processing
TODO: Add pattern generalization to regex
TODO: Test with larger attack datasets
"""

import os
import sys
from collections import Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))


class AttackPatternExtractor:
    
    def __init__(self, min_pattern_length=3, min_occurrence_ratio=0.3):
        self.min_pattern_length = min_pattern_length
        self.min_occurrence_ratio = min_occurrence_ratio
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=1000)
    
    def cluster_similar_payloads(self, payloads, distance_threshold=0.5, min_cluster_size=2):
        if len(payloads) < min_cluster_size:
            return {}
        
        try:
            payload_vectors = self.vectorizer.fit_transform(payloads)
        except Exception:
            return {}
        
        clustering = DBSCAN(eps=distance_threshold, min_samples=min_cluster_size, metric='cosine')
        cluster_labels = clustering.fit_predict(payload_vectors.toarray())
        
        clusters = {}
        for index, label in enumerate(cluster_labels):
            if label == -1:
                continue
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(payloads[index])
        
        return clusters
    
    def find_frequent_substrings(self, strings, min_length=3):
        if not strings:
            return []
        
        substring_frequency = Counter()
        
        for text in strings:
            seen_in_text = set()
            for length in range(min_length, min(len(text) + 1, 20)):
                for start in range(len(text) - length + 1):
                    substring = text[start:start + length]
                    if substring not in seen_in_text:
                        seen_in_text.add(substring)
                        substring_frequency[substring] += 1
        
        min_occurrences = len(strings) * self.min_occurrence_ratio
        frequent = [(sub, count / len(strings)) 
                    for sub, count in substring_frequency.items()
                    if count >= min_occurrences]
        
        frequent.sort(key=lambda x: (-len(x[0]), -x[1]))
        return frequent
    
    def extract_attack_patterns(self, attack_payloads):
        print(f"Extracting patterns from {len(attack_payloads)} payloads...")
        
        extracted_patterns = []
        already_found = set()
        
        frequent_substrings = self.find_frequent_substrings(attack_payloads)
        
        for substring, frequency in frequent_substrings[:20]:
            is_contained_in_existing = any(substring in p for p in already_found)
            if not is_contained_in_existing:
                extracted_patterns.append({
                    'pattern': substring,
                    'frequency': frequency,
                    'extraction_method': 'substring_analysis',
                    'sample_payloads': [p for p in attack_payloads if substring in p][:3]
                })
                already_found.add(substring)
            
            if len(extracted_patterns) >= 5:
                break
        
        payload_clusters = self.cluster_similar_payloads(attack_payloads)
        for cluster_id, cluster_payloads in payload_clusters.items():
            cluster_substrings = self.find_frequent_substrings(cluster_payloads)
            if cluster_substrings:
                best_match = cluster_substrings[0]
                if best_match[0] not in already_found:
                    extracted_patterns.append({
                        'pattern': best_match[0],
                        'frequency': best_match[1],
                        'extraction_method': f'cluster_{cluster_id}',
                        'sample_payloads': cluster_payloads[:3]
                    })
                    already_found.add(best_match[0])
        
        print(f"Found {len(extracted_patterns)} patterns")
        return extracted_patterns


if __name__ == "__main__":
    print("Testing Pattern Extractor...")
    
    test_payloads = [
        "' OR 1=1--",
        "' OR 2=2--",
        "' OR 100=100--",
        "' OR 'a'='a",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "admin'--",
        "admin' OR '1'='1",
    ]
    
    extractor = AttackPatternExtractor()
    patterns = extractor.extract_attack_patterns(test_payloads)
    
    print(f"\nPatterns found:")
    for p in patterns:
        print(f"  - '{p['pattern']}' (freq: {p['frequency']:.0%})")
