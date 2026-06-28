import subprocess
from datetime import datetime
from pathlib import Path
from modules import utils
from modules import parser

def run_scan():
    print("\n====================================================")
    print(" RUN NUCLEI - ALL CVE TEMPLATES")
    print("====================================================")

    nuclei = utils.find_nuclei()
    if not nuclei:
        print("[ERROR] Nuclei not found. Run option [3] first.")
        return

    targets_file = utils.CONFIG_DIR / "targets.txt"
    if not targets_file.exists():
        print("[INFO] targets.txt not found. Attempting to generate from inventory...")
        if not utils.generate_targets_from_inventory():
            print(f"[ERROR] targets.txt not found and could not be generated.")
            print(f"Please run baseline scan [1] or create {targets_file}")
            return

    cve_template_dir = utils.RULES_DIR / "http" / "cves"
    if not cve_template_dir.exists():
        print(f"[ERROR] CVE template folder not found: {cve_template_dir}")
        print("Run option [3] to clone/update templates.")
        return

    utils.ensure_directories()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = utils.EVIDENCE_DIR / "scanner-output"
    output_file = output_dir / f"nuclei-all-cves-{timestamp}.jsonl"

    print(f"[INFO] Target file: {targets_file}")
    print(f"[INFO] CVE templates: {cve_template_dir}")
    print(f"[INFO] Output JSONL: {output_file}")

    command = [
        nuclei,
        "-l", str(targets_file),
        "-t", str(cve_template_dir),
        "-rl", "5",
        "-c", "2",
        "-jsonl",
        "-o", str(output_file)
    ]

    print("\n[RUN] " + " ".join(command))
    
    try:
        subprocess.run(command)
    except FileNotFoundError:
        print(f"[ERROR] Failed to run Nuclei command.")
        return

    if output_file.exists() and output_file.stat().st_size > 0:
        print("\n[FOUND] Nuclei has findings.")
        print(f"[INFO] Saved JSONL: {output_file}")
        
        # Trigger the parser
        parser.parse_file(str(output_file))
        
    else:
        print("\n[NO MATCH] Scan completed but no CVE template matched.")
