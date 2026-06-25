# core/config.py
#
# Local secrets file. DO NOT COMMIT THIS FILE TO GIT.
# Make sure "core/config.py" is listed in your .gitignore (see config.py.example
# for the template that's safe to commit instead).
#
# Get a free WhoisJSON API key (1,000 requests/month, no card required) at:
# https://whoisjson.com/free-domain-api

WHOISJSON_API_KEY = "f13ddd59c18f14a4bf26c1bc753c14f36fabac1be551150361839746545b6f2a"

# --- Threat Intelligence (used by core/intel_engine.py) ---
# Leave any of these as None until you have a key -- IntelEngine handles
# missing keys gracefully and just skips that source with a clear message.
#
# Shodan:     https://account.shodan.io/  (free tier available)
# VirusTotal: https://www.virustotal.com/gui/my-apikey  (free tier available)
# AbuseIPDB:  https://www.abuseipdb.com/account/api  (free tier available)
SHODAN_API_KEY = "FQy4HArVdBbZ87AHrbfdhSXRgyE5NUbrh6GaL8enMUeh"
VIRUSTOTAL_API_KEY = "b1b88ba07430133bbba0ab41f66c6ff8f3b0640a81ee2ff9b8b75125641e75c5"
ABUSEIPDB_API_KEY = "74a2d5c1891f05c4d71326eb8f1ecacbfc116528eb0f905441626570afb9b15d11a5b2734a0295ae"