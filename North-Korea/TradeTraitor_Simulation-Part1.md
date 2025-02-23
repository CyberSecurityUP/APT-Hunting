# 🔥 **Adversary Simulation: TraderTraitor** 🔥  

The **TraderTraitor** attack is a campaign attributed to the **Lazarus Group** (DPRK), targeting **cryptocurrency developers** and **fintechs**. This attack leverages **spear-phishing**, social engineering, and **supply chain compromises** to distribute **trojans** and **backdoors** on **macOS** and **Windows** systems.

---

## 🕵 **Modus Operandi**  

### **1️⃣ Initial Reconnaissance and Targeting**
- Attackers use **social engineering** and **spear-phishing** as initial vectors.
- Fake recruiter accounts on **LinkedIn**, **WhatsApp**, and **Telegram** offer "job opportunities" to developers.
- Malicious documents (PDF, DOCX) or messages with **phishing links** direct victims to compromised websites.

### **2️⃣ Infection and Exploitation**
- Victims are lured into downloading **TraderTraitor**, a trojanized version of legitimate software (e.g., TokenAIS, CryptAIS, AlticGO).
- The malicious code uses the **Electron Framework**, allowing **cross-platform execution** (Windows/macOS).
- The `UpdateCheckSync()` function appears to check for updates but actually downloads malicious payloads from the **C2 server**.

### **3️⃣ Persistence Establishment**
- The malware **steals credentials** and creates **LaunchAgents** (`.plist`) on **macOS** for persistence.
- On **Windows**, PowerShell scripts modify **registry keys** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) to maintain access.
- **Evasion techniques** include **AES-256 encryption** and **fileless execution** via PowerShell.

### **4️⃣ Payload Execution and C2 Communication**
- The malware collects system details (user, privileges, OS).
- It establishes a **C2 channel** via **HTTP/HTTPS**, **SOCKS4/SOCKS5 proxies**, or even **WebSockets**.
- **Dynamic domain infrastructure** (`.onion`, CDN-based endpoints) is used to evade detection.

### **5️⃣ Exfiltration and Lateral Movement**
- Once inside the network, the attacker uses:
  - **Mimikatz** to extract credentials.
  - **SSH Tunneling** and **ProxyChains** for persistent communication.
  - **Living Off The Land (LOTL)** techniques to remain undetected.
- Stolen data includes **credentials, cryptocurrency wallet keys, and network information**.

### **6️⃣ Covering Tracks**
- The malware **cleans up logs** (`Clear-EventLog`, `wevtutil`).
- **Self-deletion modules** remove traces after exfiltration.
- **Fake alerts** and **false positives** are injected to mislead forensic analysis.

---

## **🔥 Cyber Kill Chain 🔥**

| **Phase**  | **Technique** |
|-----------|------------|
| **Reconnaissance** | Spear-phishing, Social Engineering, OSINT on LinkedIn |
| **Weaponization** | TraderTraitor trojans (`.exe`, `.dmg`, `.sh`) |
| **Delivery** | Malicious emails, LinkedIn messages, downloads from cloned websites |
| **Exploitation** | Payload execution via `Electron.js` |
| **Installation** | Persistence via **LaunchAgents (macOS)**, **Registry (Windows)** |
| **C2** | Encrypted communication using **dynamic domains** |
| **Exfiltration** | Credential theft, cryptocurrency wallet key extraction |

---

## **🔥 MITRE ATT&CK Techniques Used 🔥**

### **🔹 Initial Access**
- 📌 **T1566.002** - Spear-phishing via links  
- 📌 **T1566.001** - Spear-phishing via attachments  

### **🔹 Execution**
- 📌 **T1059.001** - Script execution (JavaScript, PowerShell)  
- 📌 **T1204.002** - Execution of malware via social engineering  

### **🔹 Persistence**
- 📌 **T1547.001** - Windows Registry Run Keys  
- 📌 **T1543.003** - macOS Launch Daemons  
- 📌 **T1546.015** - Persistent execution via AppleScript  

### **🔹 Evasion**
- 📌 **T1027** - Code obfuscation  
- 📌 **T1070.004** - Log clearing  
- 📌 **T1140** - Payload decryption/unpacking  

### **🔹 Exfiltration**
- 📌 **T1041** - Data exfiltration via HTTP/HTTPS  
- 📌 **T1567** - Data transfer to remote servers  

---

## 🛠 **Red Team Tools for Simulating the Attack**
To replicate this attack in a **Red Team exercise**, the following tools can be useful:

- **Phishing & C2:**
  - Gophish
  - Evilginx2
  - Cobalt Strike
  - SliverC2

- **Persistence & Evasion:**
  - Metasploit
  - Empire
  - SharpHound + BloodHound
  - Koadic
  - SILENTTRINITY

- **Payload Delivery:**
  - MacroPack
  - Bettercap (for Man-in-the-Middle)
  - MITMf

- **Post-Exploitation & Exfiltration:**
  - Mimikatz
  - Rubeus
  - SharpHound
  - PowerSploit
  - Covenant

---

## 🔥 **Adversary Simulation: Execution Steps**
To simulate this attack, the flow would be:

1️⃣ **Set up a phishing server** using **Evilginx2** and craft a malicious email with **Gophish**.  
2️⃣ **Use Bettercap** to capture network traffic and confirm if the victim clicks the link.  
3️⃣ **Send a malicious payload** (`TraderTraitor-mod.exe`) generated with **Cobalt Strike**.  
4️⃣ **Monitor logs and detections** using **Splunk, Velociraptor, or Sysmon**.  
5️⃣ **Exfiltrate data** via a **Ngrok server or Chisel VPN**.  

# TraderTraitor Attack Campaign - Others TTPs and Cyber Kill Chain

## 1. Overview
The **TraderTraitor** campaign is a North Korean cyber threat operation targeting cryptocurrency firms through spear-phishing campaigns and trojanized applications. This simulation will recreate a **Red Team exercise** using real-world **TTPs** (Tactics, Techniques, and Procedures) based on the **MITRE ATT&CK** framework and cyber kill chain analysis.

## 2. Cyber Kill Chain
### **Reconnaissance**
- [TA0043] **Gathering Email Addresses (T1589.002)**: Collect emails of employees at cryptocurrency firms via OSINT (LinkedIn, forums, company websites).
- [TA0043] **Gather Victim Information (T1592.002)**: Identify software and OS details of targets.

### **Weaponization**
- [TA0002] **Developing Malware (T1587.001)**: Create a trojanized JavaScript-based **Electron** application masquerading as a cryptocurrency trading tool.
- [TA0005] **Obfuscation (T1027.002)**: Use AES encryption to protect malicious payloads inside the application.

### **Delivery**
- [TA0001] **Spear-Phishing (T1566.001)**: Send phishing emails with job offers that contain malicious links to the fake trading software.
- [TA0001] **Malicious Websites (T1583.006)**: Host phishing pages that prompt users to download the malware.

### **Exploitation**
- [TA0005] **Exploit Public-Facing Application (T1190)**: If targets visit the phishing website, exploit a vulnerability (e.g., **CVE-2022-41352**) in their system.
- [TA0004] **Abuse Trusted Relationship (T1199)**: Leverage the trust of known cryptocurrency firms to enhance credibility.

### **Installation**
- [TA0003] **Execution via Malicious Application (T1204.002)**: Victims execute the trojanized software.
- [TA0003] **Execution via PowerShell (T1059.001)**: The app spawns PowerShell scripts to download additional payloads.
- [TA0004] **Persistence via Plist Modification (T1547.011)**: Create macOS **LaunchAgent** entries to maintain persistence.

### **Command & Control (C2)**
- [TA0011] **Encrypted C2 Communication (T1573.002)**: Malware communicates with **C2 servers** using AES-encrypted HTTP requests.
- [TA0011] **Domain Generation Algorithm (DGA) (T1568.002)**: Use algorithmically generated domains for redundancy.

### **Exfiltration & Impact**
- [TA0010] **Credential Theft (T1555.003)**: Extract **macOS Keychain** credentials.
- [TA0010] **Data Exfiltration over C2 Channel (T1041)**: Steal cryptocurrency private keys, authentication tokens.
- [TA0040] **Financial Theft (T1658)**: Use stolen credentials to access crypto wallets and conduct unauthorized transactions.

## 3. Adversary Emulation Plan
### Phase 1: Setup Environment
- Deploy phishing email infrastructure using **GoPhish**
- Host fake cryptocurrency trading software on compromised domains
- Use **FakeNet-NG** to simulate C2 traffic

### Phase 2: Attack Execution
- Send spear-phishing emails with malware attachments
- Deploy a trojanized **Electron app** that mimics **TokenAIS**
- Establish persistence on macOS using **LaunchAgents**

### Phase 3: Post-Exploitation
- Execute **PowerShell payloads** to collect system information
- Exfiltrate cryptocurrency wallet credentials
- Maintain access via **C2 infrastructure** using HTTPS tunnels

## 4. Tools for Simulation
### **Reconnaissance**
- **theHarvester** (Email scraping)
- **SpiderFoot** (OSINT collection)

### **Phishing & Delivery**
- **GoPhish** (Spear-phishing framework)
- **Evilginx2** (Phishing with bypass of MFA)

### **Exploitation & C2**
- **Metasploit Framework**
- **Cobalt Strike**
- **Mythic C2**
- **Sliver C2**

### **Post-Exploitation & Persistence**
- **Mimikatz** (Credential dumping)
- **LaZagne** (Extract saved passwords)
- **Empire PowerShell**

## 5. Detection & Mitigation Strategies
### **Defensive Measures**
- Implement **Application Allowlisting** to prevent execution of unauthorized apps.
- Enable **Behavioral Analysis** with EDR (e.g., CrowdStrike, SentinelOne) to detect anomalies.
- Enforce **FIDO2-based MFA** to protect credentials from phishing attacks.
- Conduct **User Awareness Training** on spear-phishing techniques.

