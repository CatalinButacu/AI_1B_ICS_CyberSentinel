import os

# ═══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
#
# For LOCAL TESTING (single machine):
#   Set environment variable: ICS_ENV=local
#   Or uncomment the line below:
#
# ENVIRONMENT = 'local'
#
# For VM TESTING (VirtualBox):
#   Keep default 'production' or set: ICS_ENV=production
#
# ═══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT = os.getenv('ICS_ENV', 'local')  # desktop
ENVIRONMENT = os.getenv('ICS_ENV', 'production')  # VM

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE URLs
# ═══════════════════════════════════════════════════════════════════════════
if ENVIRONMENT == 'local':
    # LOCAL TESTING - All services on same machine
    DETECTOR_URL = "http://localhost:5000"
    FIREWALL_URL = "http://localhost:5001"
    WEBAPP_URL = "http://localhost:5002"
else:
    # PRODUCTION (VMs) - Services on separate machines
    # Detector + Firewall on Defense VM (10.0.0.10)
    # Webapp on Target VM (10.0.0.20)
    DETECTOR_URL = "http://10.0.0.10:5000"
    FIREWALL_URL = "http://10.0.0.10:5001"
    WEBAPP_URL = "http://10.0.0.20:5002"

print(f"[CONFIG] Environment: {ENVIRONMENT}")
print(f"[CONFIG] Detector: {DETECTOR_URL}")
print(f"[CONFIG] Firewall: {FIREWALL_URL}")
print(f"[CONFIG] Webapp: {WEBAPP_URL}")

# ═══════════════════════════════════════════════════════════════════════════
# API SETTINGS
# ═══════════════════════════════════════════════════════════════════════════
API_TIMEOUT = 5
FEEDBACK_CONFIDENCE_THRESHOLD = 0.3

# ═══════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

os.makedirs(DATASETS_DIR, exist_ok=True)
