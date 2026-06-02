import os
import datetime
import csv

LOG_DIR = "logs"
REPORT_DIR = "reports"

# Shadow IT domains with risk levels
SHADOW_IT_DOMAINS = {
    "dropbox.com": "HIGH",
    "telegram.org": "MEDIUM",
    "discord.com": "MEDIUM",
    "mega.nz": "HIGH",
    "wetransfer.com": "LOW",
    "slack.com": "LOW"
}

def clean_old_reports():
    os.makedirs(REPORT_DIR, exist_ok=True)
    txt_path = os.path.join(REPORT_DIR, "shadowit_report.txt")
    csv_path = os.path.join(REPORT_DIR, "shadowit_report.csv")
    for file in [txt_path, csv_path]:
        if os.path.exists(file):
            os.remove(file)

def get_shadow_domains():
    domains = set()
    dns_path = os.path.join(LOG_DIR, "dns.log")
    if not os.path.exists(dns_path):
        return domains

    with open(dns_path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) > 9:
                query = parts[9].lower()
                for d in SHADOW_IT_DOMAINS.keys():
                    if d in query:
                        domains.add(d)
    return domains

def correlate_ips(domains):
    results = []
    seen = set()  # store unique (timestamp, domain, user_ip, server_ip)
    conn_path = os.path.join(LOG_DIR, "conn.log")

    if not os.path.exists(conn_path):
        return results

    with open(conn_path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) > 4:
                ts_epoch = float(parts[0])
                ts = datetime.datetime.fromtimestamp(ts_epoch).strftime('%Y-%m-%d %H:%M:%S')

                src_ip = parts[2]  # USER IP
                dst_ip = parts[4]  # SERVER IP

                for domain in domains:
                    key = (ts, domain, src_ip, dst_ip)
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "timestamp": ts,
                            "domain": domain,
                            "user_ip": src_ip,
                            "server_ip": dst_ip,
                            "risk": SHADOW_IT_DOMAINS.get(domain, "MEDIUM")
                        })
    return results

def generate_report(results):
    os.makedirs(REPORT_DIR, exist_ok=True)
    txt_path = os.path.join(REPORT_DIR, "shadowit_report.txt")
    csv_path = os.path.join(REPORT_DIR, "shadowit_report.csv")

    # TXT REPORT
    with open(txt_path, "w") as f:
        f.write("SHADOW IT DETECTION REPORT\n")
        f.write(f"Generated on: {datetime.datetime.now()}\n\n")

        if not results:
            f.write("[-] No Shadow IT activity detected\n")
            return

        for item in results:
            f.write(f"Timestamp                  : {item['timestamp']}\n")
            f.write(f"Unauthorized Domain Detected : {item['domain']}\n")
            f.write(f"User IP (Source)            : {item['user_ip']}\n")
            f.write(f"Server IP (Destination)    : {item['server_ip']}\n")
            f.write(f"Risk Level                 : {item['risk']}\n")
            f.write("Recommendation              : Block or Monitor\n")
            f.write("-" * 55 + "\n")

    # CSV REPORT
    with open(csv_path, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "domain", "user_ip", "server_ip", "risk"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)

    print("[+] Shadow IT report generated successfully (TXT + CSV)")

if __name__ == "__main__":
    clean_old_reports()  # 🔥 delete old reports first

    if not os.path.exists(LOG_DIR) or not os.listdir(LOG_DIR):
        print("[-] No Zeek logs found. Run Zeek first.")
        exit()

    domains = get_shadow_domains()
    if not domains:
        print("[-] No Shadow IT activity detected in dns.log")
        exit()

    results = correlate_ips(domains)
    generate_report(results)
