import requests
import whois
from urllib.parse import urlparse
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
from dotenv import load_dotenv
import os

# ✅ Load API Key Securely
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")


# ✅ Threat Score Calculator
def calculate_threat_score(ssl, domain_age_days, malicious):
    score = 0

    if not ssl:
        score += 20

    if domain_age_days < 180:
        score += 30

    if malicious > 0:
        score += 70

    return min(score, 100)


# ✅ Domain Age
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days

    except:
        return -1

    return -1


# ✅ VirusTotal Scan
def virustotal_scan(url):
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"

        headers = {
            "x-apikey": API_KEY
        }

        data = {"url": url}

        response = requests.post(vt_url, headers=headers, data=data)

        if response.status_code != 200:
            return -1

        analysis_url = response.json()["data"]["links"]["self"]

        result = requests.get(analysis_url, headers=headers).json()

        stats = result["data"]["attributes"]["last_analysis_stats"]

        return stats["malicious"]

    except:
        return -1


# ✅ Scan Function
def scan():
    url = entry.get().strip()

    if not url:
        messagebox.showerror("Error", "Enter a valid URL")
        return

    parsed = urlparse(url)

    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)

    domain = parsed.netloc

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, "Scanning target...\nPlease wait...\n")
    root.update()

    # SSL Check
    ssl_present = url.startswith("https")

    # Domain Age
    domain_age = get_domain_age(domain)

    # VirusTotal
    malicious = virustotal_scan(url)

    threat_score = calculate_threat_score(
        ssl_present,
        domain_age if domain_age != -1 else 999,
        malicious if malicious != -1 else 0
    )

    # Result Text
    result = "\n========== SCAN RESULT ==========\n\n"

    result += f"URL: {url}\n\n"

    result += "SSL Status: "
    result += "✔ Secure\n" if ssl_present else "❌ Not Secure\n"

    if domain_age != -1:
        result += f"Domain Age: {domain_age} days\n"
    else:
        result += "Domain Age: Unknown\n"

    if malicious > 0:
        result += f"VirusTotal: 🚨 MALICIOUS ({malicious} engines flagged)\n"
    elif malicious == 0:
        result += "VirusTotal: ✔ Clean\n"
    else:
        result += "VirusTotal: Could not scan\n"

    result += f"\n🔥 Threat Score: {threat_score}/100\n"

    if threat_score > 70:
        result += "🚨 HIGH RISK — DO NOT OPEN\n"
    elif threat_score > 40:
        result += "⚠ SUSPICIOUS — CAUTION ADVISED\n"
    else:
        result += "✔ SAFE\n"

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result)


# ✅ GUI Design
root = tk.Tk()
root.title("Hacker Forensic Scanner PRO")
root.geometry("750x520")
root.configure(bg="#0b0f14")

title = tk.Label(
    root,
    text="⚡ Sajawal Hacke URL Scanner PRO",
    font=("Helvetica", 20, "bold"),
    fg="#00ffcc",
    bg="#0b0f14"
)
title.pack(pady=20)

entry = tk.Entry(
    root,
    font=("Helvetica", 14),
    width=55,
    bg="#111827",
    fg="#00ffcc",
    insertbackground="white"
)
entry.pack(pady=10)
entry.insert(0, "Enter or Paste URL Here...")

scan_btn = tk.Button(
    root,
    text="SCAN NOW",
    font=("Helvetica", 14, "bold"),
    bg="#00ffcc",
    fg="black",
    command=scan
)
scan_btn.pack(pady=15)

result_box = tk.Text(
    root,
    height=16,
    width=85,
    bg="#111827",
    fg="#00ffcc",
    font=("Courier", 10)
)
result_box.pack(pady=10)

root.mainloop()
