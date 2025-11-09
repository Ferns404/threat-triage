import sys
import hashlib
import os
import requests
import docker
import time
from dotenv import load_dotenv
import diff_match_patch as dmp_module
import pefile # <-- NEW: Import pefile for Upgrade 2

# --- Setup ---
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# --- Static Analysis Functions (Unchanged) ---

def get_hashes(filepath):
    """Calculates all hashes for a given file."""
    print(f"[+] Calculating hashes for: {filepath}\n")
    hashes = {}
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
            
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            print(f"  MD5:    {md5_hash}")
            print(f"  SHA1:   {sha1_hash}")
            print(f"  SHA256: {sha256_hash}")
            
            return {"md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash}
            
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    except Exception as e:
        print(f"[ERROR] An error occurred getting hashes: {e}")
        return None

def query_virustotal(sha256_hash):
    """Queries the VirusTotal API for a report on the file hash."""
    print("\n[+] Querying VirusTotal API...\n")
    
    if not VT_API_KEY:
        print("  [ERROR] VT_API_KEY not found. Did you create your .env file?")
        return

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = stats.get("harmless", 0) + suspicious + malicious
            
            print(f"  Report for: {attributes.get('meaningful_name', 'N/A')}")
            print(f"  VT Score:   {malicious} Malicious / {total} Total Vendors")
            
        elif response.status_code == 404:
            print(f"  [INFO] Hash {sha256_hash} not found in VirusTotal.")
        else:
            print(f"  [ERROR] API Error. Status Code: {response.status_code}")
            
    except Exception as e:
        print(f"[ERROR] An error occurred querying VT: {e}")

# --- Advanced Static Analysis (PE Files) ---

# Dictionary of suspicious function imports
SUSPICIOUS_IMPORTS = {
    "kernel32.dll": [
        "createremotethread", "writeprocessmemory", "virtualallocex", "openprocess",
        "createprocess", "loadlibrarya", "getprocaddress"
    ],
    "ws2_32.dll": ["socket", "connect", "bind", "listen"],
    "advapi32.dll": ["regcreatekey", "regsetvalue"],
    "urlmon.dll": ["urldownloadtofilea"],
    "wininet.dll": ["internetopena", "internetopenurla"]
}

def pe_file_analysis(filepath):
    """Analyzes a Windows PE file for suspicious imports."""
    print("\n[+] Running PE File Analysis...\n")
    
    try:
        # Check for 'MZ' magic bytes at the beginning of the file
        with open(filepath, 'rb') as f:
            if f.read(2) != b'MZ':
                print("  [INFO] File is not a Windows PE file (no MZ header). Skipping.")
                return

        # File is a PE, so we can parse it
        pe = pefile.PE(filepath)
        found_suspicious = False
        
        print("  [+] Analyzing imported functions (DLLs)...")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8').lower()
                
                if dll_name in SUSPICIOUS_IMPORTS:
                    suspicious_functions = SUSPICIOUS_IMPORTS[dll_name]
                    
                    for func in entry.imports:
                        func_name = func.name.decode('utf-8').lower()
                        if func_name in suspicious_functions:
                            print(f"  [!] SUSPICIOUS: Found {dll_name} -> {func_name}")
                            found_suspicious = True
                            
        if not found_suspicious:
            print("  [INFO] No highly suspicious imports found.")
            
    except Exception as e:
        print(f"  [ERROR] PE file analysis failed: {e}")


# --- Helper function for printing the "diff" ---

def print_diff(before_snapshot, after_snapshot):
    """Compares snapshots and prints a human-readable diff."""
    dmp = dmp_module.diff_match_patch()
    diffs = dmp.diff_main(before_snapshot, after_snapshot)
    dmp.diff_cleanupSemantic(diffs)
    
    has_changes = False
    print("\n  [+] Dynamic Analysis Results:")
    
    for (op, data) in diffs:
        # Clean up "noise" from the diff
        clean_data = "\n".join([
            line for line in data.splitlines() 
            if "docker" not in line and "ps aux" not in line and "ls -laR" not in line and "PID" not in line
        ])
        
        if not clean_data.strip():
            continue

        if op == dmp.DIFF_INSERT: # This means something was ADDED
            print(f"  [+] Added Content (File or Process):\n{clean_data}\n")
            has_changes = True
        elif op == dmp.DIFF_DELETE: # This means something was DELETED
            print(f"  [-] Deleted Content (File or Process):\n{clean_data}\n")
            has_changes = True
                
    if not has_changes:
        print("  [INFO] No significant filesystem or process changes detected.")

# --- Dynamic Analysis Functions (Modified) ---

def run_command_in_container(container, command):
    """Helper function to run a command and get its output."""
    exec_result = container.exec_run(command)
    return exec_result.output.decode('utf-8')

def dynamic_analysis(filepath):
    """Runs the file in a disposable Docker sandbox."""
    print("\n[+] Starting Dynamic Analysis (Sandbox)...\n")
    
    try:
        client = docker.from_env()
        client.ping() 
        print("  [INFO] Docker connection successful.")
    except Exception as e:
        print("  [ERROR] Docker is not running or not found. Please start Docker Desktop.")
        print(f"          {e}")
        return

    container = None
    try:
        print("  [INFO] Starting sandbox container...")
        container = client.containers.run(
            'threat-triage-sandbox', 
            detach=True,             
            tty=True                 
        )
        time.sleep(2) 

        # The snapshot command now ALSO lists processes
        snapshot_command = "ls -laR /sandbox /tmp && ps aux"
        
        # 3. Take "Before" Snapshot
        print("  [INFO] Taking 'Before' filesystem & process snapshot...")
        before_snapshot = run_command_in_container(container, snapshot_command)

        # 4. Copy the "malware" into the container
        file_to_analyze_full_path = os.path.abspath(filepath)
        malware_path_in_container = f"/sandbox/{os.path.basename(filepath)}"
        
        print(f"  [INFO] Copying {filepath} into the sandbox...")
        os.system(f"docker cp \"{file_to_analyze_full_path}\" {container.id}:{malware_path_in_container}")

        # 5. "Detonate" the file
        print(f"  [!!!] DETONATING '{filepath}' IN SANDBOX...")
        run_command_in_container(container, f"chmod +x {malware_path_in_container}")
        run_command_in_container(container, malware_path_in_container)
        print("  [INFO] Detonation complete.")
        time.sleep(1) 

        # 6. Take "After" Snapshot
        print("  [INFO] Taking 'After' filesystem & process snapshot...")
        after_snapshot = run_command_in_container(container, snapshot_command)

        # 7. Compare snapshots
        # This function will now print the diff for us
        print_diff(before_snapshot, after_snapshot)
            
    except docker.errors.ImageNotFound:
        print("  [ERROR] Image 'threat-triage-sandbox' not found.")
        print("          Did you run 'docker build -t threat-triage-sandbox .'?")
    except Exception as e:
        print(f"  [ERROR] An error occurred during dynamic analysis: {e}")
        
    finally:
        # 8. Destroy the container (ALWAYS do this)
        if container:
            print(f"\n  [INFO] Destroying sandbox container ({container.id[:12]})...")
            container.stop()
            container.remove()
            print("  [INFO] Sandbox destroyed. System is clean.")

# --- Main script execution ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python triage.py <filepath>")
        sys.exit(1) 
        
    file_to_analyze = sys.argv[1]
    
    print("--- [ THREAT TRIAGE STATIC ANALYSIS ] ---")
    hash_results = get_hashes(file_to_analyze)
    
    if hash_results:
        query_virustotal(hash_results["sha256"])
        
    # Run the PE file analysis
    pe_file_analysis(file_to_analyze)
        
    print("\n--- [ THREAT TRIAGE DYNAMIC ANALYSIS ] ---")
    dynamic_analysis(file_to_analyze)
    
    print("\n--- [ TRIAGE REPORT COMPLETE ] ---")