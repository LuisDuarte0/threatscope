import os
from dotenv import load_dotenv

load_dotenv()

# --- API Keys ---
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_API_KEY        = os.getenv("VT_API_KEY", "")

# --- API Base URLs ---
OTX_BASE_URL       = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
VT_BASE_URL        = "https://www.virustotal.com/api/v3"

# --- Database ---
DB_PATH = "threatscope.db"

# --- Collection settings ---
OTX_PULSE_LIMIT     = 20   # pulses per collection run
ABUSEIPDB_LIMIT     = 100  # IPs per collection run
CONFIDENCE_DAYS     = 30   # AbuseIPDB lookback window

# --- Scoring weights ---
WEIGHT_OTX        = 0.35
WEIGHT_ABUSEIPDB  = 0.40
WEIGHT_VT         = 0.25

# --- Severity thresholds ---
SEVERITY_CRITICAL = 80
SEVERITY_HIGH     = 60
SEVERITY_MEDIUM   = 40
SEVERITY_LOW      = 0

# --- IoC types ---
IOC_TYPES = ["IPv4", "IPv6", "domain", "hostname", "URL", "FileHash-MD5",
             "FileHash-SHA1", "FileHash-SHA256"]

# --- App settings ---
APP_TITLE   = "ThreatScope"
APP_ICON    = "🔭"
APP_VERSION = "1.0.0"
REFRESH_INTERVAL_MINUTES = 30
