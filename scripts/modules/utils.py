import os
import json
import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path.home() / "hieu-early-warning"
CONFIG_DIR = BASE_DIR / "config"
EVIDENCE_DIR = BASE_DIR / "evidence"
RULES_DIR = BASE_DIR / "rules" / "projectdiscovery" / "nuclei-templates"

def ensure_directories():
    directories = [
        CONFIG_DIR,
        EVIDENCE_DIR / "baseline",
        EVIDENCE_DIR / "scanner-output",
        EVIDENCE_DIR / "rule-match",
        RULES_DIR.parent,
        BASE_DIR / "reports",
        BASE_DIR / "logs"
    ]
    for d in directories:
        d.mkdir(parents=True, exist_ok=True)

def ensure_scope_targets():
    scope_file = CONFIG_DIR / "scope-targets.txt"
    if not scope_file.exists():
        scope_file.write_text("https://127.0.0.1:8443\n", encoding="utf-8")
        print(f"[INFO] Created default scope targets at: {scope_file}")
    return scope_file

def generate_targets_from_inventory():
    inventory_file = CONFIG_DIR / "service-inventory.json"
    targets_file = CONFIG_DIR / "targets.txt"
    
    if not inventory_file.exists():
        print("[WARNING] service-inventory.json not found. Cannot generate targets.txt.")
        return False
        
    try:
        with open(inventory_file, 'r', encoding='utf-8') as f:
            inventory = json.load(f)
            
        targets = []
        for service in inventory:
            if service.get("reachable"):
                targets.append(service.get("target"))
                
        if targets:
            targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
            print(f"[INFO] Generated targets.txt with {len(targets)} reachable targets.")
            return True
        else:
            print("[WARNING] No reachable targets found in inventory.")
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to generate targets from inventory: {e}")
        return False

def find_nuclei():
    nuclei_path = shutil.which("nuclei")
    if nuclei_path:
        return nuclei_path

    go_nuclei = Path.home() / "go" / "bin" / "nuclei"
    if go_nuclei.exists():
        return str(go_nuclei)

    return None

def update_nuclei_and_templates():
    print("\n====================================================")
    print(" UPDATE NUCLEI + TEMPLATES")
    print("====================================================")

    nuclei = find_nuclei()

    if nuclei:
        print(f"[OK] nuclei found: {nuclei}")
        subprocess.run([nuclei, "-update"])
        subprocess.run([nuclei, "-update-templates"])
    else:
        print("[INFO] nuclei not found. Installing with Go...")
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"])
        nuclei = find_nuclei()

        if nuclei:
            print(f"[OK] nuclei installed: {nuclei}")
        else:
            print("[ERROR] nuclei install failed")
            return

    if RULES_DIR.exists():
        print("[INFO] Updating local nuclei-templates with git pull...")
        subprocess.run(["git", "pull"], cwd=RULES_DIR)
    else:
        print("[INFO] Cloning full ProjectDiscovery nuclei-templates...")
        RULES_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git",
            "clone",
            "https://github.com/projectdiscovery/nuclei-templates.git",
            str(RULES_DIR)
        ])

    print("\n[DONE] Update completed.")

def check_structure():
    print("\n====================================================")
    print(" SYSTEM CHECK")
    print("====================================================")
    
    # Check directories
    ensure_directories()
    print("[OK] Directory structure verified.")
    
    # Check scope
    ensure_scope_targets()
    print("[OK] Scope targets verified.")
    
    # Check nuclei
    nuclei = find_nuclei()
    if nuclei:
        print(f"[OK] Nuclei found at: {nuclei}")
    else:
        print("[WARNING] Nuclei NOT found. Run update option to install.")
        
    print("\n[DONE] Check completed.")

def write_json(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def append_jsonl(filepath, data):
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")
