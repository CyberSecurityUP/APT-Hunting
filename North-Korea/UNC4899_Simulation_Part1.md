# **🔥 Adversary Simulation: UNC4899 🔥**  

UNC4899 is a **North Korean state-sponsored threat actor** that has been **actively targeting supply chains**, **cryptocurrency firms**, and **Brazilian enterprises**. Their **modus operandi** combines **supply chain compromises**, **spear-phishing**, and **custom malware** to achieve long-term persistence and **financially motivated intrusions**.

---

## **🕵 Modus Operandi**  

### **1️⃣ Initial Access (Spear-Phishing & Supply Chain Compromise)**
- Attackers **target software providers** (e.g., **JumpCloud**) to inject malicious updates.
- They send **spear-phishing emails** with:
  - Fake job offers (LinkedIn, WhatsApp, Telegram)
  - Malicious PDFs and DOCX files
  - Trojanized cryptocurrency applications (**TraderTraitor** variants)
- Attackers **compromise the supply chain**, allowing them to **pivot into victim networks**.

### **2️⃣ Execution & Exploitation**
- Attackers deploy **custom payloads**, including:
  - **FULLHOUSE.DOORED** (first-stage backdoor)
  - **STRATOFEAR** (modular backdoor)
  - **TIEDYE** (advanced backdoor with encrypted C2 communication)
- The payloads are executed **via JumpCloud's agent**, allowing them to:
  - **Bypass traditional security controls**.
  - **Blend in with legitimate software updates**.

### **3️⃣ Persistence & Defense Evasion**
- **Windows Persistence**:
  - **Registry Run Keys**: (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
  - **DLL Sideloading** in Microsoft Teams & Zoom services.
- **macOS Persistence**:
  - **LaunchAgents & LaunchDaemons** (`.plist` modifications)
  - **Binary renaming** (e.g., masquerading as **Docker**, **Google Updater**, and **Zoom Services**).
- **Evasion Techniques**:
  - **Fileless Execution** via PowerShell.
  - **VPN + ORB Infrastructure** to obfuscate origins.
  - **Payload encryption** with AES-128 & AES-256.

### **4️⃣ C2 Communication & Data Exfiltration**
- Establishes **C2 channels** over:
  - **HTTPS**, **SOCKS4/5**, and **Custom TCP protocols**.
  - **VPN obfuscation** (ExpressVPN, NordVPN, TorGuard).
- Attackers move **laterally** using:
  - **SSH tunnels**
  - **Mimikatz for credential dumping**
  - **RDP pivoting** to expand access
- Data exfiltrated includes:
  - **Cryptocurrency wallets**
  - **Sensitive corporate data**
  - **Confidential government information**

### **5️⃣ Covering Tracks**
- **Log deletion** (`Clear-EventLog`, `wevtutil`, `auditpol`)
- **Disabling security tools** using:
  - `taskkill /IM defender.exe`
  - `Set-MpPreference -DisableRealtimeMonitoring $true`
- **Self-deletion scripts** remove artifacts post-infection.

---

## **🔥 Cyber Kill Chain 🔥**

| **Phase**  | **Technique** |
|-----------|------------|
| **Reconnaissance** | OSINT (LinkedIn, Telegram), Supply Chain Targeting |
| **Weaponization** | Trojanized applications (`.exe`, `.dmg`), Exploits in JumpCloud |
| **Delivery** | Spear-phishing, Malicious Cloud Deployments (GCP, AWS, Azure) |
| **Exploitation** | Payload execution via JumpCloud agent |
| **Installation** | Persistence via **LaunchAgents (macOS)**, **Registry (Windows)** |
| **C2** | Encrypted communication via **VPN & Proxy Chains** |
| **Exfiltration** | Credential theft, cryptocurrency wallet key extraction |

---

## **🔥 MITRE ATT&CK Techniques Used 🔥**

### **🔹 Initial Access**
- 📌 **T1566.002** - Spear-phishing via malicious links  
- 📌 **T1195.002** - Supply Chain Compromise (JumpCloud attack)  

### **🔹 Execution**
- 📌 **T1059.001** - JavaScript & PowerShell execution  
- 📌 **T1204.002** - User execution (Social Engineering)  

### **🔹 Persistence**
- 📌 **T1547.001** - Windows Registry Run Keys  
- 📌 **T1543.003** - macOS Launch Daemons  
- 📌 **T1546.015** - AppleScript Persistence  

### **🔹 Evasion**
- 📌 **T1027** - Code obfuscation  
- 📌 **T1070.004** - Log clearing  
- 📌 **T1140** - Payload decryption/unpacking  

### **🔹 Exfiltration**
- 📌 **T1041** - Data exfiltration via HTTP/HTTPS  
- 📌 **T1567** - Data transfer to remote servers  

---

## **🛠 Red Team Tools for Simulating the Attack**
For **Red Team exercises**, the following tools can replicate the attack chain:

- **Phishing & C2:**
  - Evilginx2
  - Gophish
  - SliverC2
  - Cobalt Strike

- **Persistence & Evasion:**
  - Metasploit
  - Empire
  - Koadic
  - SharpHound + BloodHound
  - SILENTTRINITY

- **Payload Delivery:**
  - MacroPack
  - MITMf (Man-in-the-Middle)
  - Bettercap

- **Post-Exploitation & Exfiltration:**
  - Mimikatz
  - Rubeus
  - SharpHound
  - PowerSploit
  - Covenant

---

## **🎯 Where to Insert the Images?**
The images you uploaded can be used in the following sections:

1. **JumpCloud Supply Chain Attack Diagram (1st Image)**
   - 📍 **Insert in the "Execution & Exploitation" section**  
   - **Explanation:** Shows how an attacker **compromised JumpCloud** to inject malicious payloads.

2. **North Korean VPN & C2 Infrastructure (2nd Image)**
   - 📍 **Insert in the "C2 and Exfiltration" section**  
   - **Explanation:** Illustrates the **use of VPNs, ORBs, and proxy chains** to evade attribution.

---

## **🔥 Adversary Simulation: Execution Steps**
To simulate this attack in a **Red Team exercise**, follow these steps:

1️⃣ **Setup a phishing campaign** using **Evilginx2 + Gophish** to steal credentials.  
2️⃣ **Deploy a fake JumpCloud update** using **Metasploit or Empire** to inject a payload.  
3️⃣ **Execute an obfuscated payload** (`UNC4899-backdoor.exe`) via **Cobalt Strike Beacon**.  
4️⃣ **Maintain persistence** by modifying **Windows Registry & macOS LaunchAgents**.  
5️⃣ **Exfiltrate data** via **reverse SSH tunnel (Chisel VPN) or SOCKS5 proxy**.  

---

### **🚀 Conclusion**
UNC4899 is a **highly sophisticated** North Korean **state-sponsored APT** that utilizes **supply chain attacks**, **VPN obfuscation**, and **stealthy malware** to achieve financial gain. Their focus on **cryptocurrency theft**, **Brazilian enterprises**, and **software providers** highlights the **increasing danger of state-sponsored financial cybercrime**.

**Defenders must:**  
✅ Strengthen **supply chain security**  
✅ Use **behavioral anomaly detection**  
✅ Monitor **unusual VPN traffic & proxy usage**  
✅ Implement **endpoint hardening & threat hunting**  

https://cloud.google.com/blog/topics/threat-intelligence/north-korea-supply-chain/

https://cloud.google.com/blog/topics/threat-intelligence/cyber-threats-targeting-brazil

https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a

https://www.npa.go.jp/bureau/cyber/pdf/20250204_tt.pdf

https://malpedia.caad.fkie.fraunhofer.de/actor/tradertraitor
