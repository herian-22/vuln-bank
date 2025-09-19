import json
import sys

MAX_FINDINGS_PER_TYPE = 3 # Batasi jumlah detail per jenis temuan agar ringkasan tidak terlalu panjang

def parse_gitleaks(data):
    if not data:
        return "Tidak ada temuan."
    
    summary_lines = []
    count = 0
    for finding in data:
        if count >= MAX_FINDINGS_PER_TYPE:
            summary_lines.append(f"• dan {len(data) - count} temuan lainnya...")
            break
        
        desc = finding.get("Description", "Aturan tidak diketahui")
        file = finding.get("File", "File tidak diketahui")
        line = finding.get("StartLine", "?")
        secret = finding.get("Secret", "secret")
        
        summary_lines.append(f"• **{desc}** di `{file}:{line}` (Contoh: `{secret[:15]}...`)")
        count += 1
        
    return "\n".join(summary_lines) if summary_lines else "Tidak ada temuan."

def parse_bandit(data):
    results = data.get("results")
    if not results:
        return "Tidak ada temuan."
    
    summary_lines = []
    count = 0
    for result in results:
        if count >= MAX_FINDINGS_PER_TYPE:
            summary_lines.append(f"• dan {len(results) - count} temuan lainnya...")
            break
            
        test_name = result.get("test_name", "Tes tidak diketahui")
        filename = result.get("filename", "File tidak diketahui")
        line = result.get("line_number", "?")
        
        summary_lines.append(f"• **{test_name}** di `{filename}:{line}`")
        count += 1
        
    return "\n".join(summary_lines) if summary_lines else "Tidak ada temuan."

def parse_trivy(data):
    results = data.get("Results")
    if not results or "Vulnerabilities" not in results[0]:
        return "Tidak ada temuan."
    
    summary_lines = []
    count = 0
    vulnerabilities = results[0].get("Vulnerabilities", [])
    if not vulnerabilities:
        return "Tidak ada temuan."
        
    for vuln in vulnerabilities:
        if count >= MAX_FINDINGS_PER_TYPE:
            summary_lines.append(f"• dan {len(vulnerabilities) - count} kerentanan lainnya...")
            break
            
        severity = vuln.get("Severity", "UNKNOWN")
        pkg_name = vuln.get("PkgName", "N/A")
        vuln_id = vuln.get("VulnerabilityID", "N/A")
        
        summary_lines.append(f"• **{severity}**: {vuln_id} di paket `{pkg_name}`")
        count += 1
        
    return "\n".join(summary_lines) if summary_lines else "Tidak ada temuan."

def parse_zap(data):
    try:
        alerts = data.get("site", [])[0].get("alerts", [])
        if not alerts:
            return "Tidak ada temuan."
        
        summary_lines = []
        count = 0
        for alert in alerts:
            if count >= MAX_FINDINGS_PER_TYPE:
                summary_lines.append(f"• dan {len(alerts) - count} peringatan lainnya...")
                break
                
            risk = alert.get("risk", "Unknown")
            name = alert.get("name", "Unknown Alert")
            url = alert.get("instances", [{}])[0].get("uri", "N/A")
            
            summary_lines.append(f"• **{risk}**: {name} di `{url.split('?')[0]}`")
            count += 1
            
        return "\n".join(summary_lines) if summary_lines else "Tidak ada temuan."
    except (IndexError, KeyError):
        return "Tidak ada temuan."

def main():
    report_type = sys.argv[1]
    filepath = sys.argv[2]

    try:
        with open(filepath, 'r') as f:
            # Handle empty file case
            content = f.read()
            if not content:
                print("Tidak ada temuan (file kosong).")
                return
            data = json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Tidak ada temuan atau file {filepath} rusak.")
        return

    parsers = {
        "gitleaks": parse_gitleaks,
        "bandit": parse_bandit,
        "trivy": parse_trivy,
        "zap": parse_zap,
    }

    if report_type in parsers:
        summary = parsers[report_type](data)
        print(summary)
    else:
        print(f"Tipe laporan tidak dikenal: {report_type}")

if __name__ == "__main__":
    main()