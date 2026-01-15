import os
import platform

def detect_environment():
    system = platform.system().lower()
    is_vm = os.path.exists('/media/sf_src') or os.path.exists('/mnt/sf_src')
    
    env_override = os.getenv('ICS_ENV')
    if env_override:
        return env_override
    
    if system == 'windows':
        return 'local'
    elif is_vm:
        return 'production'
    else:
        return 'local'

ENVIRONMENT = detect_environment()

if ENVIRONMENT == 'local':
    DETECTOR_URL = "http://localhost:5000"
    FIREWALL_URL = "http://localhost:5001"
    WEBAPP_URL = "http://localhost:5002"
else:
    DETECTOR_URL = "http://10.0.0.10:5000"
    FIREWALL_URL = "http://10.0.0.10:5001"
    WEBAPP_URL = "http://10.0.0.20:5002"

print(f"[CONFIG] Environment: {ENVIRONMENT}")
print(f"[CONFIG] Detector: {DETECTOR_URL}")
print(f"[CONFIG] Firewall: {FIREWALL_URL}")
print(f"[CONFIG] Webapp: {WEBAPP_URL}")

API_TIMEOUT = 5
FEEDBACK_CONFIDENCE_THRESHOLD = 0.3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

os.makedirs(DATASETS_DIR, exist_ok=True)
