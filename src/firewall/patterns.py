import os
import sys
import re
from collections import Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))


class AnomalyDetector:
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 5), max_features=500)
        self.is_trained = False
    
    def train(self, normal_queries):
        if len(normal_queries) < 10:
            return False
        
        try:
            vectors = self.vectorizer.fit_transform(normal_queries)
            self.model.fit(vectors.toarray())
            self.is_trained = True
            return True
        except Exception:
            return False
    
    def is_anomaly(self, query):
        if not self.is_trained:
            return False, 0.0
        
        try:
            vector = self.vectorizer.transform([query])
            prediction = self.model.predict(vector.toarray())
            score = self.model.score_samples(vector.toarray())[0]
            return prediction[0] == -1, abs(score)
        except Exception:
            return False, 0.0


class PatternGeneralizer:
    
    @staticmethod
    def to_sql_regex(pattern):
        generalizations = []
        
        if re.search(r"OR\s+\d+\s*=\s*\d+", pattern, re.I):
            generalizations.append(r"^.*OR\s+\d+\s*=\s*\d+.*$")
        
        if re.search(r"UNION\s+SELECT", pattern, re.I):
            generalizations.append(r"^.*UNION\s+(ALL\s+)?SELECT.*$")
        
        if '--' in pattern or '/*' in pattern:
            generalizations.append(r"^.*(--|/\*|#).*$")
        
        return generalizations


class AttackPatternExtractor:
    
    def __init__(self, min_pattern_length=3, min_occurrence_ratio=0.3):
        self.min_pattern_length = min_pattern_length
        self.min_occurrence_ratio = min_occurrence_ratio
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=1000)
        self.anomaly_detector = AnomalyDetector()
        self.pattern_generalizer = PatternGeneralizer()
    
    def cluster_similar_payloads(self, payloads, distance_threshold=0.5, min_cluster_size=2):
        if len(payloads) < min_cluster_size:
            return {}
        
        try:
            vectors = self.vectorizer.fit_transform(payloads)
        except Exception:
            return {}
        
        clustering = DBSCAN(eps=distance_threshold, min_samples=min_cluster_size, metric='cosine')
        labels = clustering.fit_predict(vectors.toarray())
        
        clusters = {}
        for index, label in enumerate(labels):
            if label == -1:
                continue
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(payloads[index])
        
        return clusters
    
    def find_frequent_substrings(self, strings, min_length=3):
        if not strings:
            return []
        
        frequency = Counter()
        
        for text in strings:
            seen = set()
            for length in range(min_length, min(len(text) + 1, 20)):
                for start in range(len(text) - length + 1):
                    substring = text[start:start + length]
                    if substring not in seen:
                        seen.add(substring)
                        frequency[substring] += 1
        
        min_count = len(strings) * self.min_occurrence_ratio
        frequent = [(sub, count / len(strings)) for sub, count in frequency.items() if count >= min_count]
        frequent.sort(key=lambda x: (-len(x[0]), -x[1]))
        
        return frequent
    
    def extract_attack_patterns(self, attack_payloads):
        print(f"Extracting patterns from {len(attack_payloads)} payloads...")
        
        extracted = []
        already_found = set()
        
        frequent = self.find_frequent_substrings(attack_payloads)
        
        for substring, freq in frequent[:20]:
            is_substring_of_existing = any(substring in p for p in already_found)
            if not is_substring_of_existing:
                regex_variants = self.pattern_generalizer.to_sql_regex(substring)
                
                extracted.append({
                    'pattern': substring,
                    'frequency': freq,
                    'method': 'substring',
                    'regex_variants': regex_variants
                })
                already_found.add(substring)
            
            if len(extracted) >= 5:
                break
        
        clusters = self.cluster_similar_payloads(attack_payloads)
        for cluster_id, cluster_payloads in clusters.items():
            cluster_substrings = self.find_frequent_substrings(cluster_payloads)
            if cluster_substrings:
                best = cluster_substrings[0]
                if best[0] not in already_found:
                    extracted.append({
                        'pattern': best[0],
                        'frequency': best[1],
                        'method': f'cluster_{cluster_id}'
                    })
                    already_found.add(best[0])
        
        print(f"Found {len(extracted)} patterns")
        return extracted
    
    def check_anomaly(self, query):
        return self.anomaly_detector.is_anomaly(query)


if __name__ == "__main__":
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
    
    print("\nPatterns found:")
    for p in patterns:
        print(f"  '{p['pattern']}' (freq: {p['frequency']:.0%})")
