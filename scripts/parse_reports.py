import json
import sys

def get_logical_risk(tool, finding):
    """Memberikan penjelasan risiko logis berdasarkan jenis temuan."""
    if tool == "gitleaks":
        desc = finding.get("Description", "").lower()
        if "api" in desc or "key" in desc or "secret" in desc:
            return "Risiko: Kunci ini dapat disalahgunakan untuk mengakses layanan pihak ketiga atas nama Anda, menyebabkan potensi penyalahgunaan atau kerugian finansial."
    elif tool == "bandit":
        test_name = finding.get("test_name", "")
        if "hardcoded_sql_expressions" in test_name:
            return "Risiko: Potensi SQL Injection yang dapat menyebabkan bypass otentikasi atau kebocoran data dari database."
        if "hardcoded_password" in test_name:
            return "Risiko: Password yang ditulis langsung di kode memudahkan peretas untuk mendapatkan akses tidak sah jika kode sumber bocor."
        if "exec_used" in test_name or "shell" in test_name:
            return "Risiko: Penggunaan perintah shell yang tidak aman dapat dieksploitasi untuk menjalankan perintah berbahaya di server (Remote Code Execution)."
    elif tool == "trivy":
        severity = finding.get("Severity", "")
        if severity == "CRITICAL":
            return "Risiko: Kerentanan Kritis pada library yang digunakan dapat dieksploitasi oleh peretas untuk mengambil alih server atau menyebabkan kerusakan signifikan."
        if severity == "HIGH":
            return "Risiko: Kerentanan Tinggi pada library dapat dieksploitasi untuk mencuri data sensitif atau menyebabkan penolakan layanan (DoS)."
    elif tool == "zap":
        name = finding.get("name", "").lower()
        if "sql injection" in name:
            return "Risiko: Aplikasi rentan terhadap SQL Injection, memungkinkan peretas memanipulasi database, mencuri data, atau bahkan mengambil alih server."
        if "cross-site scripting" in name:
            return "Risiko: Kerentanan XSS memungkinkan peretas menyisipkan skrip berbahaya di halaman web yang dapat mencuri cookie sesi atau data pengguna lain."
        if "security policy (csp) header not set" in name:
            return "Risiko: Tanpa CSP, pertahanan terhadap serangan XSS menjadi lemah, memudahkan peretas memuat skrip dari sumber eksternal yang tidak terpercaya."
    return "Risiko: Temuan ini dapat berdampak pada keamanan dan stabilitas aplikasi."

def parse_gitleaks(data):
    if not data:
        return "Tidak ada temuan."

    # Prioritaskan temuan yang mengandung kata 'key', 'secret', 'token'
    priority_finding = next((f for f in data if any(k in f.get("Description", "").lower() for k in ["api", "key", "secret", "token"])), data[0])

    desc = priority_finding.get("Description", "Aturan tidak diketahui")
    file = priority_finding.get("File", "File tidak diketahui")
    line = priority_finding.get("StartLine", "?")
    risk = get_logical_risk("gitleaks", priority_finding)

    summary = (
        f"**Temuan Paling Kritis**: {desc}\n"
        f"**Lokasi**: `{file}` pada baris `{line}`\n"
        f"**{risk}**\n"
        f"*(Total {len(data)} temuan terdeteksi)*"
    )
    return summary

def parse_bandit(data):
    results = data.get("results")
    if not results:
        return "Tidak ada temuan."

    # Prioritaskan SQL injection, hardcoded password, atau shell injection
    priority_order = ["hardcoded_sql_expressions", "hardcoded_password", "shell"]
    priority_finding = results[0]
    for p in priority_order:
        finding = next((r for r in results if p in r.get("test_name", "")), None)
        if finding:
            priority_finding = finding
            break

    test_name = priority_finding.get("test_name", "Tes tidak diketahui")
    filename = priority_finding.get("filename", "File tidak diketahui")
    line = priority_finding.get("line_number", "?")
    risk = get_logical_risk("bandit", priority_finding)

    summary = (
        f"**Temuan Paling Kritis**: {test_name}\n"
        f"**Lokasi**: `{filename}` pada baris `{line}`\n"
        f"**{risk}**\n"
        f"*(Total {len(results)} temuan terdeteksi)*"
    )
    return summary

def parse_trivy(data):
    results = data.get("Results")
    if not results or "Vulnerabilities" not in results[0]:
        return "Tidak ada temuan."

    vulnerabilities = results[0].get("Vulnerabilities", [])
    if not vulnerabilities:
        return "Tidak ada temuan."

    # Prioritaskan kerentanan CRITICAL, lalu HIGH
    priority_finding = next((v for v in vulnerabilities if v.get("Severity") == "CRITICAL"), vulnerabilities[0])

    severity = priority_finding.get("Severity", "UNKNOWN")
    pkg_name = priority_finding.get("PkgName", "N/A")
    vuln_id = priority_finding.get("VulnerabilityID", "N/A")
    risk = get_logical_risk("trivy", priority_finding)

    summary = (
        f"**Temuan Paling Kritis**: {vuln_id} ({severity})\n"
        f"**Lokasi**: Paket `{pkg_name}`\n"
        f"**{risk}**\n"
        f"*(Total {len(vulnerabilities)} kerentanan terdeteksi)*"
    )
    return summary

def parse_zap(data):
    try:
        alerts = data.get("site", [])[0].get("alerts", [])
        if not alerts:
            return "Tidak ada temuan."

        # Prioritaskan SQL Injection, XSS, atau CSP
        priority_order = ["sql injection", "cross-site scripting", "content security policy"]
        priority_finding = alerts[0]
        for p in priority_order:
            finding = next((a for a in alerts if p in a.get("name", "").lower()), None)
            if finding:
                priority_finding = finding
                break

        name = priority_finding.get("name", "Unknown Alert")
        risk_level = priority_finding.get("risk", "Unknown")
        risk = get_logical_risk("zap", priority_finding)

        summary = (
            f"**Temuan Paling Kritis**: {name} ({risk_level})\n"
            f"**Lokasi**: Terjadi pada respons HTTP dari server.\n"
            f"**{risk}**\n"
            f"*(Total {len(alerts)} peringatan terdeteksi)*"
        )
        return summary
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
            data = json.loads(content) if content.strip() else {}
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