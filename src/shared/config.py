"""
Shared Configuration for ICS Security Project
"""

import os

ENVIRONMENT = os.getenv('ICS_ENV', 'local')

if ENVIRONMENT == 'local':
    DETECTOR_URL = "http://localhost:5000"
    FIREWALL_URL = "http://localhost:5001"
    WEBAPP_URL = "http://localhost:5002"
else:
    DETECTOR_URL = "http://10.0.0.10:5000"
    FIREWALL_URL = "http://10.0.0.1:5001"
    WEBAPP_URL = "http://10.0.0.20:5002"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

os.makedirs(DATASETS_DIR, exist_ok=True)

API_TIMEOUT = 5
FEEDBACK_CONFIDENCE_THRESHOLD = 0.8

RESOURCES = {
    'datasets': {
        'sqli_kaggle': 'https://www.kaggle.com/datasets/sajid576/sql-injection-dataset',
        'payloads': 'https://github.com/swisskyrepo/PayloadsAllTheThings',
    },
    'papers': {
        'deepsqli': 'https://arxiv.org/abs/2006.02654',
        'ml_cybersecurity': 'https://arxiv.org/abs/2004.11894',
    }
}
