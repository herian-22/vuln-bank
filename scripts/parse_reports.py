import json
import sys

def parse_gitleaks(data):
    if not data:
        return "Tidak ada temuan."
    # Menghitung temuan berdasarkan deskripsinya
    summary = {}
    for finding in data:
        desc = finding.get("Description", "Unknown Rule")
        summary[desc] = summary.get(desc, 0) + 1
    return "\n".join([f"• {count}x {desc}" for desc, count in summary.items()])

def parse_bandit(data):
    results = data.get("results")
    if not results:
        return "Tidak ada temuan."
    # Menghitung temuan berdasarkan nama tes
    summary = {}
    for result in results:
        name = result.get("test_name", "Unknown Test")
        summary[name] = summary.get(name, 0) + 1
    return "\n".join([f"• {count}x {name}" for name, count in summary.items()])

def parse_trivy(data):
    results = data.get("Results")
    if not results or "Vulnerabilities" not in results[0]:
        return "Tidak ada temuan."
    # Menghitung kerentanan berdasarkan tingkat keparahan (Severity)
    summary = {}
    vulnerabilities = results[0].get("Vulnerabilities", [])
    if not vulnerabilities:
        return "Tidak ada temuan."
    for vuln in vulnerabilities:
        severity = vuln.get("Severity", "UNKNOWN")
        summary[severity] = summary.get(severity, 0) + 1
    return "\n".join([f"• {count}x {severity}" for severity, count in summary.items()])

def parse_zap(data):
    try:
        alerts = data.get("site", [])[0].get("alerts", [])
        if not alerts:
            return "Tidak ada temuan."
        # Menghitung peringatan berdasarkan deskripsi risiko
        summary = {}
        for alert in alerts:
            risk = alert.get("riskdesc", "Unknown Risk")
            summary[risk] = summary.get(risk, 0) + 1
        return "\n".join([f"• {count}x {risk}" for risk, count in summary.items()])
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