# Consolidated setup (Fedora)

### **Phase 1: System Prep (Run as Root/Sudo)**

First, install the necessary system tools and create the isolated user. Fedora often ships without the cron daemon enabled by default.

```bash
# 1. Install Python and Cron
sudo dnf install -y python3 python3-pip cronie nano

# 2. Enable and start the Cron service
sudo systemctl enable --now crond

# 3. Create the dedicated user (sis-scanner)
# We create a home directory (-m) and set the shell to bash (-s)
sudo useradd -m -s /bin/bash sis-scanner

# 4. Switch to the new user for the rest of the setup
sudo -i -u sis-scanner

```

---

### **Phase 2: Directory & Environment Setup (Run as `sis-scanner`)**

Now that you are logged in as `sis-scanner`, set up the folder structure and secrets.

#### **1. Create Directories**

```bash
mkdir -p ~/corpus
mkdir -p ~/scripts

```

#### **2. Create the Secret File**

Store your API key securely.

```bash
nano ~/.env.prod

```

*Paste the following (replace with your actual key):*

```bash
MWB_API_KEY="your_actual_key_here"

```

*Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).*

*Secure the file:*

```bash
chmod 600 ~/.env.prod

```

#### **3. Python Virtual Environment**

Set up the environment exactly as you described (`.venv` in the home root).

```bash
cd ~
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install requests pyzipper

# (Optional) Freeze to requirements.txt for record keeping
pip freeze > requirements.txt

# Deactivate for now
deactivate

```

---

### **Phase 3: The Scripts**

#### **1. The Python Tool (`fetch_pdfs.py`)**

This script handles the API query, shuffling, downloading, and unzipping.

```bash
nano ~/scripts/fetch_pdfs.py

```

*Paste the complete, fixed code:*

```python
import os
import sys
import json
import random
import datetime
import time
import requests
import pyzipper

# --- CONFIGURATION ---
API_KEY = os.getenv("MWB_API_KEY")
# Determine where this script is located so we can find relative paths if needed
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# We assume the wrapper sets the CWD to the data directory, but we can also force it:
# ROOT_DIR = os.path.expanduser("~/corpus") 
MWB_API_URL = "https://mb-api.abuse.ch/api/v1/"
DAILY_LIMIT = 20
ZIP_PASSWORD = b"infected"

def query_recent_pdfs(limit=100):
    print(f"[*] Querying MalwareBazaar for recent PDFs (fetching pool of {limit})...")
    
    # AUTH CHECK: Abuse.ch uses 'Auth-Key'
    headers = {"Auth-Key": API_KEY}
    data = {
        "query": "get_file_type",
        "file_type": "pdf",
        "limit": str(limit)
    }
    
    try:
        response = requests.post(MWB_API_URL, data=data, headers=headers, timeout=15)
        response.raise_for_status()
        json_resp = response.json()
        
        if json_resp.get("query_status") != "ok":
            print(f"[!] API Error: {json_resp.get('query_status')}")
            return []
            
        return json_resp.get("data", [])
    except requests.exceptions.HTTPError as err:
        if err.response.status_code == 401:
            print("[!] 401 Unauthorized. Server rejected the key.")
        else:
            print(f"[!] HTTP Error: {err}")
        return []
    except Exception as e:
        print(f"[!] Failed to query API: {e}")
        return []

def download_sample(file_hash, dest_folder):
    headers = {"Auth-Key": API_KEY}
    data = {"query": "get_file", "sha256_hash": file_hash}

    try:
        response = requests.post(MWB_API_URL, data=data, headers=headers, stream=True, timeout=30)
        if "file_not_found" in response.text:
            return None

        temp_zip = os.path.join(dest_folder, f"{file_hash}.zip")
        with open(temp_zip, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        extracted_name = None
        try:
            with pyzipper.AESZipFile(temp_zip) as zf:
                zf.pwd = ZIP_PASSWORD
                for member in zf.namelist():
                    zf.extract(member, path=dest_folder)
                    final_path = os.path.join(dest_folder, f"{file_hash}.pdf")
                    os.rename(os.path.join(dest_folder, member), final_path)
                    print(f"    [+] Downloaded: {file_hash}.pdf")
                    extracted_name = f"{file_hash}.pdf"
                    break 
        except Exception as zip_err:
            print(f"[!] Zip Error {file_hash}: {zip_err}")
            return None
        finally:
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
        
        return extracted_name
    except Exception as e:
        print(f"[!] Download Error {file_hash}: {e}")
        return None

def main():
    if not API_KEY:
        print("[-] Error: MWB_API_KEY not set.")
        sys.exit(1)

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    # Current Working Directory is set by the wrapper script to ~/corpus
    cwd = os.getcwd()
    target_dir_name = f"mwb-{today}"
    target_path = os.path.join(cwd, target_dir_name)
    manifest_path = os.path.join(cwd, f"manifest-{target_dir_name}.json")

    if not os.path.exists(target_path):
        os.makedirs(target_path)
    
    candidates = query_recent_pdfs(limit=100)
    if not candidates:
        print("[!] No candidates found.")
        sys.exit(1)

    random.shuffle(candidates)
    successful_samples = []
    
    print(f"[*] Starting download of {DAILY_LIMIT} samples to {target_path}...")
    
    count = 0
    for sample in candidates:
        if count >= DAILY_LIMIT: break
            
        f_hash = sample.get("sha256_hash")
        if os.path.exists(os.path.join(target_path, f"{f_hash}.pdf")):
            print(f"    [-] Skipping {f_hash}, exists.")
            continue

        fname = download_sample(f_hash, target_path)
        if fname:
            successful_samples.append({
                "filename": fname,
                "sha256": f_hash,
                "tags": sample.get("tags"),
                "signature": sample.get("signature"),
                "first_seen": sample.get("first_seen"),
                "download_date": today
            })
            count += 1
            time.sleep(1)

    with open(manifest_path, "w") as f:
        json.dump(successful_samples, f, indent=4)
        
    print(f"[*] Done. {len(successful_samples)} samples in {manifest_path}")

if __name__ == "__main__":
    main()

```

#### **2. The Wrapper Script (`run_daily.sh`)**

This handles the environment activation and logging.

```bash
nano ~/scripts/run_daily.sh

```

*Paste this code:*

```bash
#!/bin/bash

# --- CONFIGURATION ---
USER_HOME="/home/sis-scanner"
ENV_FILE="$USER_HOME/.env.prod"
VENV_ACTIVATE="$USER_HOME/.venv/bin/activate"
SCRIPT_DIR="$USER_HOME/scripts"
DATA_DIR="$USER_HOME/corpus"
LOG_FILE="$USER_HOME/scripts/download.log"

# --- 1. Load Secrets ---
if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "[!] Critical: $ENV_FILE not found." >> "$LOG_FILE"
    exit 1
fi

# --- 2. Activate Virtual Environment ---
if [ -f "$VENV_ACTIVATE" ]; then
    source "$VENV_ACTIVATE"
else
    echo "[!] Critical: Virtual environment not found at $VENV_ACTIVATE" >> "$LOG_FILE"
    exit 1
fi

# --- 3. Execution ---
# Move to DATA_DIR so the python script writes ./mwb-DATE folders there
cd "$DATA_DIR" || { echo "[!] Failed to cd to $DATA_DIR" >> "$LOG_FILE"; exit 1; }

echo "--- Starting run: $(date) ---" >> "$LOG_FILE"

# Run python (this uses the python from the activated venv)
python3 "$SCRIPT_DIR/fetch_pdfs.py" >> "$LOG_FILE" 2>&1

echo "--- Finished run: $(date) ---" >> "$LOG_FILE"

# Cleanup
deactivate

```

*Make it executable and private:*

```bash
chmod 700 ~/scripts/run_daily.sh

```

---

### **Phase 4: Automation (Cron)**

Set the script to run daily at 3 AM.

```bash
crontab -e

```

*Add this line:*

```cron
0 3 * * * /home/sis-scanner/scripts/run_daily.sh

```

---

### **Phase 5: Verification**

Run a manual test to ensure the permissions, paths, and API keys are correct.

```bash
~/scripts/run_daily.sh

```

**Check the results:**

1. **Log:** `cat ~/scripts/download.log` (Should show "Success").
2. **Files:** `ls -R ~/corpus` (Should see a `mwb-YYYY-MM-DD` folder and a `manifest-....json`).
