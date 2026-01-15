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


class RuleConsolidator:
    """Consolidates existing rules by clustering similar patterns and merging them."""
    
    RULES_FILE = os.path.join(os.path.dirname(__file__), 'rules', 'ai_learned.rules')
    
    def __init__(self, similarity_threshold=0.7):
        self.similarity_threshold = similarity_threshold
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=500)
    
    def load_existing_patterns(self):
        """Extract pattern strings from existing Snort rules."""
        patterns = []
        if not os.path.exists(self.RULES_FILE):
            return patterns
        
        try:
            with open(self.RULES_FILE, 'r') as f:
                for line in f:
                    # Extract content from: content:"pattern";
                    match = re.search(r'content:"([^"]+)"', line)
                    if match:
                        pattern = match.group(1)
                        # Skip Snort hex escapes like |7C|
                        pattern = re.sub(r'\|[0-9A-Fa-f]+\|', '', pattern)
                        if pattern.strip():
                            patterns.append(pattern.strip())
        except Exception as e:
            print(f"[CONSOLIDATOR] Error loading rules: {e}")
        
        return patterns
    
    def compute_similarity(self, pattern1, pattern2):
        """Compute character-level similarity between two patterns."""
        if not pattern1 or not pattern2:
            return 0.0
        
        # Quick containment check
        if pattern1 in pattern2 or pattern2 in pattern1:
            return 0.9
        
        # Character overlap ratio
        set1 = set(pattern1.lower())
        set2 = set(pattern2.lower())
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    def find_common_core(self, patterns):
        """Find the longest common substring among patterns."""
        if not patterns:
            return ""
        
        # Start with shortest pattern
        patterns = sorted(patterns, key=len)
        shortest = patterns[0]
        
        # Try finding longest common substring
        for length in range(len(shortest), 2, -1):
            for start in range(len(shortest) - length + 1):
                candidate = shortest[start:start + length]
                if all(candidate.lower() in p.lower() for p in patterns):
                    return candidate
        
        return shortest
    
    def cluster_existing_patterns(self, patterns):
        """Cluster similar patterns using DBSCAN."""
        if len(patterns) < 2:
            return {0: patterns} if patterns else {}
        
        try:
            vectors = self.vectorizer.fit_transform(patterns)
            clustering = DBSCAN(
                eps=(1 - self.similarity_threshold),
                min_samples=2,
                metric='cosine'
            )
            labels = clustering.fit_predict(vectors.toarray())
            
            clusters = {}
            noise = []
            for idx, label in enumerate(labels):
                if label == -1:
                    noise.append(patterns[idx])
                else:
                    if label not in clusters:
                        clusters[label] = []
                    clusters[label].append(patterns[idx])
            
            # Add noise as individual clusters
            for i, pattern in enumerate(noise):
                clusters[f"noise_{i}"] = [pattern]
            
            return clusters
        except Exception as e:
            print(f"[CONSOLIDATOR] Clustering error: {e}")
            return {0: patterns}
    
    def consolidate(self, existing_patterns=None):
        """Main consolidation: cluster existing patterns and return consolidated set."""
        if existing_patterns is None:
            existing_patterns = self.load_existing_patterns()
        
        if not existing_patterns:
            return []
        
        # Remove exact duplicates first
        unique_patterns = list(set(existing_patterns))
        print(f"[CONSOLIDATOR] {len(existing_patterns)} patterns → {len(unique_patterns)} unique")
        
        # Cluster similar patterns
        clusters = self.cluster_existing_patterns(unique_patterns)
        
        consolidated = []
        for cluster_id, cluster_patterns in clusters.items():
            if len(cluster_patterns) == 1:
                # Single pattern, keep as-is
                consolidated.append({
                    'pattern': cluster_patterns[0],
                    'source': 'single',
                    'merged_count': 1
                })
            else:
                # Multiple patterns, find common core
                core = self.find_common_core(cluster_patterns)
                if len(core) >= 3:
                    consolidated.append({
                        'pattern': core,
                        'source': 'merged',
                        'merged_count': len(cluster_patterns),
                        'original_patterns': cluster_patterns
                    })
                    print(f"[CONSOLIDATOR] Merged {len(cluster_patterns)} patterns → '{core}'")
                else:
                    # Core too short, keep the shortest original
                    best = min(cluster_patterns, key=len)
                    consolidated.append({
                        'pattern': best,
                        'source': 'shortest',
                        'merged_count': 1
                    })
        
        print(f"[CONSOLIDATOR] Final: {len(consolidated)} consolidated patterns")
        return consolidated
    
    def is_pattern_redundant(self, new_pattern, existing_patterns):
        """Check if a new pattern is redundant given existing patterns."""
        new_lower = new_pattern.lower()
        
        for existing in existing_patterns:
            existing_lower = existing.lower() if isinstance(existing, str) else existing.get('pattern', '').lower()
            
            # Check containment
            if new_lower in existing_lower or existing_lower in new_lower:
                return True
            
            # Check high similarity
            if self.compute_similarity(new_pattern, existing_lower) > self.similarity_threshold:
                return True
        
        return False
    
    def rewrite_rules_file(self, new_patterns=None):
        """Consolidate existing + new patterns and overwrite the rules file."""
        from rules import create_snort_rule_from_pattern
        from datetime import datetime
        
        # Load existing patterns
        existing = self.load_existing_patterns()
        
        # Add new patterns if provided
        all_patterns = existing.copy()
        if new_patterns:
            for p in new_patterns:
                pattern_str = p.get('pattern') if isinstance(p, dict) else p
                if pattern_str:
                    all_patterns.append(pattern_str)
        
        print(f"[CONSOLIDATOR] Total patterns before consolidation: {len(all_patterns)}")
        
        # Consolidate all patterns
        consolidated = self.consolidate(all_patterns)
        
        # Rewrite the rules file
        try:
            with open(self.RULES_FILE, 'w') as f:
                f.write(f"# AI-Generated Snort Rules (Consolidated)\n")
                f.write(f"# Updated: {datetime.now().isoformat()}\n")
                f.write(f"# Total consolidated rules: {len(consolidated)}\n\n")
                
                for item in consolidated:
                    pattern = item.get('pattern') if isinstance(item, dict) else item
                    if pattern and len(pattern) >= 3:
                        rule = create_snort_rule_from_pattern(pattern)
                        f.write(rule + '\n')
            
            print(f"[CONSOLIDATOR] ✅ Rewrote rules file with {len(consolidated)} consolidated rules")
            return consolidated
        except Exception as e:
            print(f"[CONSOLIDATOR] ❌ Error rewriting rules: {e}")
            return []


class AttackPatternExtractor:
    
    def __init__(self, min_pattern_length=3, min_occurrence_ratio=0.3):
        self.min_pattern_length = min_pattern_length
        self.min_occurrence_ratio = min_occurrence_ratio
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=1000)
        self.anomaly_detector = AnomalyDetector()
        self.pattern_generalizer = PatternGeneralizer()
        self.consolidator = RuleConsolidator()
    
    def cluster_similar_payloads(self, payloads, distance_threshold=0.5, min_cluster_size=5):
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
        
        # Load existing patterns to avoid duplicates
        existing_patterns = self.consolidator.load_existing_patterns()
        print(f"[EXTRACTOR] Loaded {len(existing_patterns)} existing patterns")
        
        extracted = []
        already_found = set(existing_patterns)  # Include existing patterns
        
        frequent = self.find_frequent_substrings(attack_payloads)
        
        for substring, freq in frequent[:20]:
            # Check if substring is similar to existing patterns
            is_redundant = self.consolidator.is_pattern_redundant(substring, existing_patterns)
            is_substring_of_existing = any(substring in p for p in already_found)
            
            if not is_redundant and not is_substring_of_existing:
                regex_variants = self.pattern_generalizer.to_sql_regex(substring)
                
                extracted.append({
                    'pattern': substring,
                    'frequency': freq,
                    'method': 'substring',
                    'regex_variants': regex_variants
                })
                already_found.add(substring)
            elif is_redundant:
                print(f"[EXTRACTOR] Skipped redundant: '{substring[:30]}...'")
            
            if len(extracted) >= 5:
                break
        
        clusters = self.cluster_similar_payloads(attack_payloads)
        for cluster_id, cluster_payloads in clusters.items():
            cluster_substrings = self.find_frequent_substrings(cluster_payloads)
            if cluster_substrings:
                best = cluster_substrings[0]
                is_redundant = self.consolidator.is_pattern_redundant(best[0], existing_patterns)
                if best[0] not in already_found and not is_redundant:
                    extracted.append({
                        'pattern': best[0],
                        'frequency': best[1],
                        'method': f'cluster_{cluster_id}'
                    })
                    already_found.add(best[0])
        
        print(f"Found {len(extracted)} NEW patterns (filtered out redundant)")
        return extracted
    
    def extract_and_consolidate(self, attack_payloads):
        """Extract patterns AND consolidate/overwrite the rules file."""
        # Extract new patterns
        new_patterns = self.extract_attack_patterns(attack_payloads)
        
        # Consolidate existing + new patterns and rewrite rules file
        if new_patterns:
            print(f"[EXTRACTOR] Consolidating and rewriting rules file...")
            self.consolidator.rewrite_rules_file(new_patterns)
        else:
            # Even without new patterns, consolidate existing ones
            print(f"[EXTRACTOR] No new patterns, consolidating existing rules...")
            self.consolidator.rewrite_rules_file()
        
        return new_patterns
    
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
