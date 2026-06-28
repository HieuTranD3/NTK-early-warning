import json
import re
from datetime import datetime
from pathlib import Path
from modules import utils

def get_risk_score(severity):
    severity_lower = str(severity).lower()
    risk_mapping = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 1
    }
    return risk_mapping.get(severity_lower, 0)

def get_risk_level(score):
    if score >= 10:
        return "Critical"
    elif score >= 8:
        return "High"
    elif score >= 5:
        return "Medium"
    elif score >= 2:
        return "Low"
    elif score == 1:
        return "Informational"
    return "Unknown"

def parse_file(raw_output_file):
    print("\n====================================================")
    print(" PARSE NUCLEI OUTPUT")
    print("====================================================")
    
    raw_path = Path(raw_output_file)
    if not raw_path.exists() or raw_path.stat().st_size == 0:
        print("[WARNING] Raw output file is missing or empty.")
        return

    # Load service inventory for matching
    inventory_file = utils.CONFIG_DIR / "service-inventory.json"
    inventory = []
    if inventory_file.exists():
        try:
            with open(inventory_file, 'r', encoding='utf-8') as f:
                inventory = json.load(f)
        except Exception:
            pass
            
    inventory_dict = {s["target"]: s for s in inventory}

    # Extract scan_id from filename or generate one
    match = re.search(r'nuclei-all-cves-(.*?)\.jsonl', raw_path.name)
    scan_id = match.group(1) if match else datetime.now().strftime("%Y%m%d-%H%M%S")

    # Read JSONL
    lines = raw_path.read_text(errors="ignore").splitlines()
    
    parsed_findings = []
    normalized_findings = []
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0
    }
    
    highest_score = 0

    for line in lines:
        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
            
        target_val = data.get("url") or data.get("host", "")
        matched_endpoint = data.get("matched-at", "")
        finding_name = data.get("info", {}).get("name", "Unknown Finding")
        severity = data.get("info", {}).get("severity", "unknown")
        cves = data.get("info", {}).get("classification", {}).get("cve-id", [])
        
        service_info = inventory_dict.get(target_val, {})
        service_name = service_info.get("service_name", "Unknown Web Service")
        
        risk_score = get_risk_score(severity)
        highest_score = max(highest_score, risk_score)
        
        # update counts
        sev_lower = str(severity).lower()
        if sev_lower in severity_counts:
            severity_counts[sev_lower] += 1
        else:
            severity_counts["unknown"] += 1

        # Dữ liệu cho file array đơn giản
        parsed_findings.append({
            "template_id": data.get("template-id"),
            "name": finding_name,
            "severity": severity,
            "cve": cves,
            "target": target_val,
            "matched_endpoint": matched_endpoint
        })
        
        # Dữ liệu normalized chuẩn
        normalized_findings.append({
            "scan_id": scan_id,
            "environment": "local-vm",
            "service": service_name,
            "scanner": "Nuclei",
            "template_id": data.get("template-id"),
            "finding_name": finding_name,
            "severity": severity,
            "cve": cves,
            "target": target_val,
            "matched_endpoint": matched_endpoint,
            "status": "matched",
            "validation_status": "pending_validation",
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score),
            "raw_evidence_file": raw_path.name,
            "created_at": datetime.now().isoformat()
        })

    if not normalized_findings:
        print("[INFO] No valid JSON findings parsed.")
        return

    rule_match_dir = utils.EVIDENCE_DIR / "rule-match"
    
    # 1. Save parsed_finding_x.json
    existing_files = list(rule_match_dir.glob("parsed_finding_*.json"))
    max_num = 0
    pattern = re.compile(r"parsed_finding_(\d+)\.json")
    for f in existing_files:
        m = pattern.match(f.name)
        if m:
            num = int(m.group(1))
            if num > max_num:
                max_num = num
                
    next_num = max_num + 1
    parsed_output_file = rule_match_dir / f"parsed_finding_{next_num}.json"
    utils.write_json(parsed_output_file, parsed_findings)
    print(f"[INFO] Saved parsed array: {parsed_output_file}")
    
    # 2. Append to normalized-findings.jsonl
    normalized_file = rule_match_dir / "normalized-findings.jsonl"
    for item in normalized_findings:
        utils.append_jsonl(normalized_file, item)
    print(f"[INFO] Appended to: {normalized_file}")
    
    # 3. Save matched-rules.json (latest findings)
    matched_rules_file = rule_match_dir / "matched-rules.json"
    utils.write_json(matched_rules_file, normalized_findings)
    print(f"[INFO] Saved matched rules: {matched_rules_file}")
    
    # 4. Save alert-summary.json
    alert_summary = {
        "scan_id": scan_id,
        "environment": "local-vm",
        "service": list(set([f["service"] for f in normalized_findings]))[0] if normalized_findings else "Unknown",
        "total_findings": len(normalized_findings),
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "info_count": severity_counts["info"],
        "highest_risk_level": get_risk_level(highest_score),
        "alert_status": "new_alerts_generated",
        "generated_at": datetime.now().isoformat()
    }
    
    alert_summary_file = rule_match_dir / "alert-summary.json"
    utils.write_json(alert_summary_file, alert_summary)
    print(f"[INFO] Saved alert summary: {alert_summary_file}")
