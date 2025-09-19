# Dokumentasi Pipeline DevSecOps

Dokumen ini memberikan rincian teknis mengenai arsitektur dan alur kerja dari pipeline *Continuous Integration/Continuous Security* (CI/CS) yang diimplementasikan untuk aplikasi Vuln-Bank. Pipeline ini dirancang untuk mengotomatiskan serangkaian pemindaian keamanan secara sistematis pada setiap perubahan kode.

## Daftar Isi

1.  [Pengenalan Pipeline](#1-pengenalan-pipeline)
2.  [Struktur dan Alur Kerja (Workflow)](#2-struktur-dan-alur-kerja-workflow)
    *   [Pemicu (Trigger)](#pemicu-trigger)
    *   [Tahap Build](#tahap-build)
    *   [Tahap Pemindaian Keamanan](#tahap-pemindaian-keamanan)
    *   [Tahap Notifikasi](#tahap-notifikasi)
3.  [Tools yang Digunakan dan Konfigurasinya](#3-tools-yang-digunakan-dan-konfigurasinya)
    *   [Secret Scanning (Gitleaks)](#secret-scanning-gitleaks)
    *   [Software Composition Analysis (Trivy)](#software-composition-analysis-sca---trivy)
    *   [Static Application Security Testing (Bandit)](#static-application-security-testing-sast---bandit)
    *   [Misconfiguration Scanning (Trivy)](#misconfiguration-scanning-trivy)
    *   [Dynamic Application Security Testing (OWASP ZAP)](#dynamic-application-security-testing-dast---owasp-zap)
4.  [Penanganan Kerentanan dan Sistem Notifikasi](#4-penanganan-kerentanan-dan-sistem-notifikasi)
    *   [Mekanisme Penentuan Status](#mekanisme-penentuan-status)
    *   [Proses Parsing dan Agregasi Laporan](#proses-parsing-dan-agregasi-laporan)
    *   [Pengiriman Notifikasi](#pengiriman-notifikasi)

---

## 1. Pengenalan Pipeline

Pipeline DevSecOps ini adalah serangkaian proses otomatis yang terintegrasi ke dalam alur kerja pengembangan perangkat lunak (SDLC) menggunakan **GitHub Actions**. Tujuannya adalah untuk menerapkan prinsip *Shift-Left Security*, yaitu mendeteksi dan mengatasi masalah keamanan sedini mungkin dalam siklus pengembangan.

Pipeline ini mencakup lima pilar pemindaian keamanan:

*   **Secret Scanning**: Mendeteksi kredensial (API keys, password) yang tidak sengaja ter-commit.
*   **Software Composition Analysis (SCA)**: Menganalisis dependensi pihak ketiga untuk mencari kerentanan yang diketahui (CVEs).
*   **Static Application Security Testing (SAST)**: Menganalisis kode sumber secara statis untuk menemukan pola kode yang rentan.
*   **Misconfiguration Scanning**: Memeriksa kesalahan konfigurasi pada file infrastruktur seperti `Dockerfile`.
*   **Dynamic Application Security Testing (DAST)**: Menguji aplikasi yang sedang berjalan untuk menemukan kerentanan level runtime.

## 1. Struktur dan Alur Kerja Pipeline

Alur kerja pipeline didefinisikan dalam file `.github/workflows/devsecops_pipeline.yml` dan terdiri dari beberapa tahapan (*jobs*) yang dieksekusi secara berurutan dan paralel.

### Pemicu (Trigger)
Pipeline dieksekusi secara otomatis setiap kali ada event `push` ke branch `main`, atau dapat dipicu secara manual melalui `workflow_dispatch`.

```yaml
on:
  push:
    branches:
      - main
  workflow_dispatch:
```

### Tahap Build
Tahap pertama adalah `build`, yang bertanggung jawab untuk membangun Docker image dari aplikasi. Image yang berhasil dibangun kemudian disimpan sebagai *artifact* agar dapat digunakan oleh tahapan selanjutnya.

### Tahap Pemindaian Keamanan
Setelah tahap `build` selesai, lima *job* pemindaian keamanan berjalan secara paralel untuk efisiensi waktu. Setiap *job* berjalan secara independen dan menghasilkan laporan dalam format JSON.

1.  `secret_scan` (Gitleaks)
2.  `sast_scan` (Bandit)
3.  `container_scan` (Trivy SCA)
4.  `misconfig_scan` (Trivy Config)
5.  `dast_scan` (OWASP ZAP)

### Tahap Notifikasi
Tahap terakhir adalah `notify`, yang bergantung pada semua *job* pemindaian. Tahap ini akan selalu berjalan (`if: always()`) untuk memastikan laporan dikirim baik pipeline berhasil maupun gagal. Tahap ini mengumpulkan semua ringkasan, menentukan status akhir, dan mengirim notifikasi ke Discord.

## 3. Tools yang Digunakan dan Konfigurasinya

Berikut adalah rincian teknis dari setiap *tool* yang digunakan dalam pipeline.

### Secret Scanning (Gitleaks)
*   **Fungsi**: Menganalisis seluruh riwayat Git untuk mendeteksi kredensial yang tidak sengaja ter-commit.
*   **Perintah Eksekusi**:
    ```bash
    gitleaks detect --report-path gitleaks-report.json --report-format json -v
    ```
    Perintah ini memindai repositori, menghasilkan laporan dalam format JSON, dan menyertakan output verbose.

### Software Composition Analysis (SCA - Trivy)
*   **Fungsi**: Memindai dependensi di dalam Docker image untuk mengidentifikasi pustaka pihak ketiga yang memiliki kerentanan keamanan (CVEs).
*   **Perintah Eksekusi**:
    ```bash
    trivy image --format json --output trivy-report.json --severity CRITICAL,HIGH vuln-bank:${{ github.sha }}
    ```
    Perintah ini memindai Docker image yang telah dibangun, memfilter temuan hanya untuk tingkat `CRITICAL` dan `HIGH`, dan menyimpannya dalam format JSON.

### Static Application Security Testing (SAST - Bandit)
*   **Fungsi**: Menganalisis kode sumber Python secara statis untuk menemukan pola kode yang berpotensi tidak aman.
*   **Perintah Eksekusi**:
    ```bash
    pip install bandit && bandit -r . -f json -o bandit-report.json
    ```
    Bandit diinstal dan dijalankan secara rekursif (`-r .`) pada seluruh direktori proyek, dengan output format JSON.

### Misconfiguration Scanning (Trivy)
*   **Fungsi**: Memeriksa file konfigurasi seperti `Dockerfile` untuk mendeteksi kesalahan konfigurasi umum (misalnya, `run as root`).
*   **Perintah Eksekusi**:
    ```bash
    trivy config --format json --output misconfig-report.json .
    ```
    Trivy memindai file konfigurasi di direktori saat ini dan menghasilkan laporan JSON.

### Dynamic Application Security Testing (DAST - OWASP ZAP)
*   **Fungsi**: Menjalankan aplikasi dalam kontainer dan secara aktif menyerangnya untuk menemukan kerentanan runtime.
*   **Perintah Eksekusi**:
    ```bash
    docker run --network host -v $(pwd):/zap/wrk/:rw \
      ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
      -t http://127.0.0.1:5000 -J zap-report.json -l PASS
    ```
    Perintah ini menjalankan ZAP Baseline Scan terhadap aplikasi yang berjalan di `http://127.0.0.1:5000`. Laporan disimpan dalam format JSON.

## 4. Penanganan Kerentanan dan Sistem Notifikasi

Sistem notifikasi dirancang untuk memberikan umpan balik yang cepat dan dapat ditindaklanjuti.

### Mekanisme Penentuan Status
Setiap *job* pemindaian diatur dengan `continue-on-error: true` agar pipeline tidak berhenti di tengah jalan. Namun, pada tahap `notify`, hasil dari setiap *job* (`needs.<job_id>.result`) diperiksa. Jika salah satu dari hasil tersebut adalah `failure`, maka status keseluruhan pipeline akan menjadi **"Gagal"** dan warna notifikasi di Discord menjadi merah.

```bash
# Logika di dalam job 'notify'
if [ "${{ needs.secret_scan.result }}" == "failure" ] || \
   [ "${{ needs.sast_scan.result }}" == "failure" ] || \
   # ... (pemeriksaan untuk semua job)
then
  PIPELINE_STATUS="Gagal"
  PIPELINE_COLOR=15158332 # Merah
fi
```

### Proses Parsing dan Agregasi Laporan
Skrip `scripts/parse_reports.py` bertanggung jawab untuk memproses setiap laporan JSON. Skrip ini memiliki logika untuk memprioritaskan temuan yang paling kritis dan menyajikannya dalam format yang mudah dibaca.

*   **Prioritas**: Temuan seperti `CRITICAL` severity dari Trivy, `hardcoded_sql_expressions` dari Bandit, atau API key dari Gitleaks akan diutamakan.
*   **Output**: Untuk setiap jenis pemindaian, skrip menghasilkan ringkasan yang berisi:
    *   **Temuan Paling Kritis**: Nama teknis dari masalah utama.
    *   **Lokasi**: Di mana masalah itu ditemukan (file, baris, atau paket).
    *   **Penjelasan Risiko**: Dampak logis dari kerentanan tersebut.
    *   **Jumlah Total Temuan**: Memberikan konteks bahwa mungkin ada temuan lain.

### Pengiriman Notifikasi
Skrip `scripts/generate_payload.sh` menggabungkan semua ringkasan ke dalam satu payload JSON yang diformat sebagai "embed" Discord. Payload ini dikirim menggunakan `curl` ke URL webhook yang disimpan sebagai *secret* di repositori GitHub.

```bash
# Contoh eksekusi pengiriman notifikasi
JSON_PAYLOAD=$(./scripts/generate_payload.sh ...)
curl -X POST -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD" \
  ${{ secrets.DISCORD_WEBHOOK_URL }}
```

Dengan cara ini, pengembang dapat langsung melihat masalah keamanan yang paling mendesak langsung dari notifikasi Discord tanpa harus membuka setiap file laporan secara manual.

