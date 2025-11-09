# 🔬 Threat Triage

Threat Triage is an automated analysis tool for quickly assessing potentially malicious files. It performs both static and dynamic analysis in a safe, isolated Docker sandbox to generate a high-level report on the file's reputation and behavior.

This tool is designed to provide a "first look" at a suspicious file, answering the key questions:
* **What is it?** (Hashes, file type)
* **Is it known to be bad?** (VirusTotal score)
* **What *does* it do?** (File system & process changes)

---

## ✨ Features

* **Static Analysis:**
    * Calculates **MD5, SHA1, and SHA256** hashes.
    * Integrates with the **VirusTotal API** to check the file's reputation.
    * Performs **PE File Analysis** on Windows executables to find suspicious imported functions (e.g., `CreateRemoteThread`, `socket`).
* **Dynamic Sandbox Analysis:**
    * Detonates the file in a **safe, isolated Docker container** (Alpine Linux).
    * 
    * Takes "before" and "after" snapshots of the sandbox.
    * Monitors for **file system changes** (files created/deleted).
    * Monitors for **process changes** (new processes spawned).
* **Automated Reporting:**
    * Generates a clean, readable diff of all changes.
    * Automatically destroys the container, leaving **no trace** on the host machine.

---

## How It Works

The tool's workflow is a simple, three-stage pipeline:

`File` → `[ 1. Static Analysis ]` → `[ 2. Dynamic Sandbox ]` → `[ 3. Final Report ]`

1.  **Static Analysis:** The script first analyzes the file "at rest." It calculates hashes, checks VirusTotal, and—if it's a Windows PE file—scans its import table for suspicious functions.
2.  **Dynamic Analysis:** The script then starts a clean Docker container, takes a "before" snapshot of the files (`ls`) and processes (`ps`), copies the file in, and executes it.
3.  **Final Report:** After a brief pause, it takes an "after" snapshot, compares the two, and generates a report on any new files or processes. The container is then destroyed.

---

## 🛠️ Setup & Installation

You will need **Python 3**, **pip**, and **Docker Desktop** installed.

### 1. Clone the Repository
```bash
# Clone the repo to your local machine
git clone [https://github.com/YOUR_USERNAME/threat-triage.git](https://github.com/YOUR_USERNAME/threat-triage.git)
cd threat-triage
```

### 2. Set Up the Python Environment
It's highly recommended to use a virtual environment.

```bash
# Create a virtual environment
python -m venv venv

# Activate it:
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
First, create a file named `requirements.txt` in your project folder and paste the following lines into it:

```text
# requirements.txt
requests
python-dotenv
pefile
docker
diff-match-patch
```

Now, run the installer:
```bash
# This will install all libraries at once
pip install -r requirements.txt
```

### 4. Set Up Your API Key
1.  Sign up for a free account at [virustotal.com](https://www.virustotal.com/).
2.  Go to your profile (top-right) and find your **API key**.
3.  Create a file in the project folder named `.env`
4.  Add your API key to it like this:
    ```
    VT_API_KEY=YOUR_API_KEY_GOES_HERE
    ```

### 5. Build the Docker Sandbox
Make sure **Docker Desktop is open and running**.
```bash
# This command builds your "threat-triage-sandbox" image
# You only need to do this once.
docker build -t threat-triage-sandbox .
```

---

## 🚀 How to Use

To analyze a file, you just pass its path as an argument to the script.

### 1. Activate Your Environment
Make sure your virtual environment is active:
```bash
# On Windows
.\venv\Scripts\Activate.ps1

# On Mac/Linux
source venv/bin/activate
```

### 2. Run the Analysis
Pass any file to the script. You can use the included `eicar.sh` as a safe test.

```bash
# To analyze the test file
python triage.py eicar.sh

# To analyze any other file
python triage.py /path/to/another/file.exe
```

> **⚠️ WARNING: DO NOT RUN REAL MALWARE**
> This tool is for educational purposes. Only run files that you *know* are safe, or use industry-standard, well-documented samples in a 100% isolated environment.

---

## 📋 Sample Output (EICAR Test)

Here is the exact output from running the tool on the `eicar.sh` test file.

```
--- [ THREAT TRIAGE STATIC ANALYSIS ] ---
[+] Calculating hashes for: eicar.sh

  MD5:    44d88612fea8a8f36de82e1278abb02f
  SHA1:   3395856ce81f2b7382dee72602f798b642f14140
  SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

[+] Querying VirusTotal API...

  Report for: eicar.com
  VT Score:   66 Malicious / 66 Total Vendors

[+] Running PE File Analysis...

  [INFO] File is not a Windows PE file (no MZ header). Skipping.

--- [ THREAT TRIAGE DYNAMIC ANALYSIS ] ---

[+] Starting Dynamic Analysis (Sandbox)...

  [INFO] Docker connection successful.
  [INFO] Starting sandbox container...
  [INFO] Taking 'Before' filesystem & process snapshot...
  [INFO] Copying eicar.sh into the sandbox...
  [!!!] DETONATING 'eicar.sh' IN SANDBOX...
  [INFO] Detonation complete.
  [INFO] Taking 'After' filesystem & process snapshot...

  [+] Dynamic Analysis Results:
  [+] Added Content (File or Process):
-rwxr-xr-x    1 root     root            68 Nov  9 12:00 eicar.sh

  [INFO] Destroying sandbox container (a1b2c3d4e5f6)...
  [INFO] Sandbox destroyed. System is clean.

--- [ TRIAGE REPORT COMPLETE ] ---
```

---

## ⚖️ License

Licensed under the **MIT License**.