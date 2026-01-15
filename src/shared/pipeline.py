"""
Defense Pipeline Orchestrator
Author: Team

This module provides the central business logic for the 3 defense cases:
- Case 1: No defense (baseline vulnerable)
- Case 2: Inline ML Detection (each querry goes through ML)
- Case 3: Full Pipeline (Firewall with feedback loop)

The pipeline is used by webapp.py to check requests BEFORE executing SQL.
"""

import os
import sys
import requests
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from shared.config import DETECTOR_URL, FIREWALL_URL, API_TIMEOUT


class DefensePipeline:
    """
    Orchestrates the defense layers based on the configured case.
    
    Usage:
        pipeline = DefensePipeline(case=2)
        is_allowed, reason, details = pipeline.check_request(user_input)
        
        if not is_allowed:
            log_incident(user_input, reason)
            return None  # Block the request
    """
    
    def __init__(self, case: int = 1):
        """
        Initialize the pipeline with a specific case.
        
        Args:
            case: 1 = No defense, 2 = Detector only, 3 = Firewall + Detector
        """
        self.case = case
        self.incidents = []
        
        # Service URLs
        self.detector_url = DETECTOR_URL
        self.firewall_url = FIREWALL_URL
        
        print(f"[PIPELINE] Initialized with Case {case}")
        if case >= 2:
            print(f"[PIPELINE] Detector service expected at: {self.detector_url}")
        if case >= 3:
            print(f"[PIPELINE] Firewall service expected at: {self.firewall_url}")
    
    def check_request(self, payload: str) -> tuple:
        """
        Check if a request should be allowed based on the current case.
        
        Returns:
            tuple: (is_allowed: bool, reason: str, details: dict)
        """
        details = {
            'case': self.case,
            'payload_preview': payload[:50] + '...' if len(payload) > 50 else payload,
            'timestamp': datetime.now().isoformat()
        }
        
        # Case 1: No defense - allow everything
        if self.case == 1:
            return (True, 'no_defense', details)
        
        # Case 3: Check Firewall FIRST (pattern matching)
        if self.case == 3:
            firewall_result = self._check_firewall(payload)
            if firewall_result['blocked']:
                details['blocked_by'] = 'firewall'
                details['pattern'] = firewall_result.get('pattern', 'unknown')
                self._log_incident(payload, 'firewall_pattern', details)
                return (False, 'blocked_by_firewall', details)
        
        # Case 2 & 3: Check ML Detector
        if self.case >= 2:
            detector_result = self._check_detector(payload)
            if detector_result['is_attack']:
                details['blocked_by'] = 'detector'
                details['confidence'] = detector_result.get('confidence', 0)
                self._log_incident(payload, 'ml_detection', details)
                
                # Case 3: Report to Firewall for learning
                if self.case == 3:
                    self._report_to_firewall(payload)
                
                return (False, f"blocked_by_detector:{detector_result.get('confidence', 0):.0%}", details)
        
        # All checks passed
        return (True, 'allowed', details)
    
    def _check_firewall(self, payload: str) -> dict:
        """Check if payload matches any known attack patterns in Firewall."""
        try:
            response = requests.post(
                f"{self.firewall_url}/check-pattern",
                json={'payload': payload},
                timeout=API_TIMEOUT
            )
            if response.status_code == 200:
                return response.json()
            return {'blocked': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            print(f"[PIPELINE] Firewall check failed: {e}")
            return {'blocked': False, 'error': str(e)}
    
    def _check_detector(self, payload: str) -> dict:
        """Check if payload is classified as attack by ML detector."""
        try:
            response = requests.post(
                f"{self.detector_url}/check",
                json={'payload': payload},
                timeout=API_TIMEOUT
            )
            if response.status_code == 200:
                return response.json()
            return {'is_attack': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            print(f"[PIPELINE] Detector check failed: {e}")
            return {'is_attack': False, 'error': str(e)}
    
    def _report_to_firewall(self, payload: str):
        """Report detected attack to Firewall for pattern learning."""
        try:
            requests.post(
                f"{self.firewall_url}/feedback",
                json={'payload': payload, 'is_attack': True},
                timeout=API_TIMEOUT
            )
            print(f"[PIPELINE] Reported to Firewall for learning")
        except Exception as e:
            print(f"[PIPELINE] Failed to report to Firewall: {e}")
    
    def _log_incident(self, payload: str, incident_type: str, details: dict):
        """Log security incident."""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'type': incident_type,
            'payload': payload[:100],
            'details': details
        }
        self.incidents.append(incident)
        
        # Console log
        print(f"[INCIDENT] {incident_type.upper()}: {payload[:40]}...")
    
    def get_incidents(self) -> list:
        """Return all logged incidents."""
        return self.incidents
    
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            'case': self.case,
            'total_incidents': len(self.incidents),
            'incidents_by_type': self._count_by_type()
        }
    
    def _count_by_type(self) -> dict:
        counts = {}
        for incident in self.incidents:
            t = incident['type']
            counts[t] = counts.get(t, 0) + 1
        return counts


# Singleton instance for webapp to use
_pipeline_instance = None

def get_pipeline(case: int = None) -> DefensePipeline:
    """Get or create the pipeline instance."""
    global _pipeline_instance
    if _pipeline_instance is None or (case is not None and _pipeline_instance.case != case):
        _pipeline_instance = DefensePipeline(case or 1)
    return _pipeline_instance
