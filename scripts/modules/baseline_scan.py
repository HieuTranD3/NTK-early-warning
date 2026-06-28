import os
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from modules import utils

def run_baseline():
    print("\n====================================================")
    print(" RUN BASELINE SCAN")
    print("====================================================")

    utils.ensure_directories()
    scope_file = utils.ensure_scope_targets()

    with open(scope_file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("[ERROR] No targets found in scope-targets.txt")
        return

    scan_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    reachability_results = []
    discovered_services = []
    
    inventory_file = utils.CONFIG_DIR / "service-inventory.json"
    
    # Load existing inventory if available
    existing_inventory = []
    if inventory_file.exists():
        try:
            with open(inventory_file, 'r', encoding='utf-8') as f:
                existing_inventory = json.load(f)
        except Exception:
            existing_inventory = []

    print(f"[INFO] Checking {len(targets)} targets...")

    reachable_count = 0

    for target in targets:
        print(f" -> Probing: {target} ... ", end="")
        
        reachable = False
        status_code = None
        server_header = None
        title = None

        try:
            # Simple HTTP request to check reachability and headers
            req = urllib.request.Request(target, method="HEAD")
            # We ignore SSL verification for local testing
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            try:
                with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                    status_code = response.getcode()
                    reachable = True
                    server_header = response.headers.get("Server", "")
            except urllib.error.HTTPError as e:
                status_code = e.code
                reachable = True
                server_header = e.headers.get("Server", "")
            except urllib.error.URLError:
                pass
                
        except Exception as e:
            pass

        if reachable:
            print(f"Reachable (HTTP {status_code})")
            reachable_count += 1
        else:
            print("Unreachable")

        reachability_results.append({
            "target": target,
            "reachable": reachable,
            "status_code": status_code
        })

        if reachable:
            protocol = target.split("://")[0] if "://" in target else "unknown"
            parts = target.split("://")[-1].split(":")
            port = int(parts[1].split("/")[0]) if len(parts) > 1 else (443 if protocol == "https" else 80)
            
            # Fingerprinting logic
            service_id = "unknown"
            service_name = "Unknown Web Service"
            criticality = "unknown"
            case_study_cve = None
            
            if "8443" in target: # naive check for OFBiz locally
                service_id = "ofbiz"
                service_name = "Apache OFBiz"
                criticality = "high"
                case_study_cve = "CVE-2024-38856"
            
            service_entry = {
                "service_id": service_id,
                "service_name": service_name,
                "target": target,
                "protocol": protocol,
                "port": port,
                "environment": "local-vm",
                "reachable": reachable,
                "status_code": status_code,
                "criticality": criticality,
                "status": "active",
                "source": "baseline_scan",
                "evidence": f"HTTP {status_code}"
            }
            if case_study_cve:
                service_entry["case_study_cve"] = case_study_cve
                
            discovered_services.append(service_entry)

    # Merge with existing inventory (simple deduplication by target)
    new_inventory_dict = {s["target"]: s for s in existing_inventory}
    for s in discovered_services:
        new_inventory_dict[s["target"]] = s
        
    final_inventory = list(new_inventory_dict.values())

    # Write output files
    utils.write_json(utils.EVIDENCE_DIR / "baseline" / "reachability-results.json", reachability_results)
    utils.write_json(utils.EVIDENCE_DIR / "baseline" / "discovered-services.json", discovered_services)
    utils.write_json(inventory_file, final_inventory)

    baseline_summary = {
        "scan_id": scan_id,
        "environment": "local-vm",
        "targets_checked": len(targets),
        "reachable_targets": reachable_count,
        "services": len(discovered_services),
        "generated_at": datetime.now().isoformat()
    }
    
    utils.write_json(utils.EVIDENCE_DIR / "baseline" / "baseline-summary.json", baseline_summary)
    utils.generate_targets_from_inventory()
    
    print("\n[DONE] Baseline scan completed.")
    print(f" -> Reachable targets: {reachable_count}")
    print(f" -> Inventory updated: {inventory_file}")
