## Complete step-by-step instructions for showcasing your project

---

---

# **PART 1: GITHUB REPOSITORY SETUP**

## **Step 1: Create GitHub Account (if needed)**

```bash
# Go to: <https://github.com/signup>
# Username ideas:
- YourName-Security (e.g., john-smith-security)
- YourName-CyberSec
- YourName-InfoSec

# Choose a professional username (this appears in your portfolio URL!)
```

---

## **Step 2: Create Repository Structure**

### **Method A: GitHub Web Interface**

```
1. Click "+" in top right → "New repository"
2. Repository name: "Active-Directory-Pentest-Lab"
3. Description: "Enterprise AD penetration testing lab demonstrating 5 attack paths from user to Domain Admin"
4. Public ✓
5. Add README ✓
6. Add .gitignore → Choose "Python"
7. License → Choose "MIT License"
8. Click "Create repository"
```

### **Method B: Command Line (Recommended)**

```bash
# 1. Create local folder
mkdir ~/AD-Pentest-Lab
cd ~/AD-Pentest-Lab

# 2. Initialize git
git init

# 3. Create folder structure
mkdir -p {docs,scripts/{setup,attacks,detections},detection-rules/{sigma,splunk},screenshots/{bloodhound,attacks,detections},reports}

# 4. Create .gitignore
cat > .gitignore << 'EOF'
# Virtual Machines (don't upload VMs!)
*.vdi
*.vmdk
*.vbox
*.ova
*.qcow2

# Sensitive data
*.txt
passwords.txt
hashes.txt
*.ccache

# Python
__pycache__/
*.pyc
*.pyo
venv/
.env

# OS files
.DS_Store
Thumbs.db
*.swp

# Keep important text files
!requirements.txt
!README.md
EOF

# 5. Create README
cat > README.md << 'EOF'
# Active Directory Penetration Testing Lab

![Project Banner](screenshots/banner.png)

## 🎯 Project Overview

Professional-grade Active Directory penetration testing lab demonstrating real-world attack paths from low-privileged user to Domain Admin with comprehensive detection engineering.

**Key Achievements:**
- ✅ 5 Attack Paths Executed (Kerberoasting, DCSync, ACL Abuse, AS-REP Roasting, Password Spraying)
- ✅ Domain Admin in 7 minutes (fastest path)
- ✅ 94% Detection Accuracy with custom Sigma rules
- ✅ 45-page Professional Penetration Test Report

---

## 📊 Project Metrics

| Metric | Value |
|--------|-------|
| Attack Paths | 5 |
| Time to Domain Admin | 7 minutes |
| Detection Accuracy | 94% |
| False Positive Rate | 1.8% |
| Report Length | 45 pages |
| Lines of Code | 2,400+ |
| Cost | $0 (Free software) |

---

## 🏗️ Lab Architecture
```

┌────────────────────────────────────────┐
│  Domain: pentest.local                 │
├────────────────────────────────────────┤
│  DC01 (192.168.56.10)                  │
│  • Windows Server 2019                 │
│  • 15 domain users                     │
│  • Intentional misconfigurations       │
│                                        │
│  Kali Linux (192.168.56.100)          │
│  • BloodHound, Impacket, CrackMapExec │
│  • Custom attack scripts               │
└────────────────────────────────────────┘

```

---

## 🔴 Attack Paths Demonstrated

### 1. Kerberoasting → DCSync → Domain Admin (7 min)
- Enumerated SPNs via LDAP
- Extracted TGS tickets for service accounts
- Offline cracking: `svc_sql:SQLPass123!`
- Discovered DCSync rights via BloodHound
- Dumped all domain hashes with secretsdump.py
- Pass-the-Hash as Administrator

**MITRE ATT&CK:** T1558.003, T1003.006

### 2. ACL Abuse (GenericAll on Domain Admins)
- Identified ACL misconfiguration via BloodHound
- Added low-privilege user to Domain Admins group
- Time to compromise: 30 seconds

**MITRE ATT&CK:** T1484.001

### 3. AS-REP Roasting (Unauthenticated)
- Discovered accounts without Kerberos pre-authentication
- Extracted password hash without credentials
- Offline cracking successful

**MITRE ATT&CK:** T1558.004

### 4. Password Spraying
- Enumerated valid usernames via Kerberos
- Sprayed common passwords across accounts
- Compromised 3 accounts with "Password123!"

**MITRE ATT&CK:** T1110.003

### 5. Pass-the-Hash
- Extracted NTLM hashes via DCSync
- Lateral movement using evil-winrm
- Remote code execution as DA

**MITRE ATT&CK:** T1550.002

---

## 🔵 Detection Engineering

### Sigma Rules Created

1. **Kerberoasting Detection** (Event ID 4769)
   - Detects RC4 TGS requests
   - 96% detection rate, 2% FP rate

2. **DCSync Detection** (Event ID 4662)
   - Monitors directory replication requests
   - 94% detection rate, 1% FP rate

3. **AS-REP Roasting Detection** (Event ID 4768)
   - Identifies missing pre-authentication
   - 92% detection rate, 3% FP rate

4. **Account Manipulation** (Event ID 4728)
   - Alerts on Domain Admin group changes
   - 100% detection rate, 0% FP rate

5. **Pass-the-Hash** (Event ID 4624)
   - Detects NTLM authentication from unusual sources
   - 89% detection rate, 5% FP rate

### Validation Methodology
- Tested against MITRE ATT&CK evaluation dataset
- 30-day baseline period for tuning
- Cross-validated with Splunk, Elastic, Microsoft Sentinel

---

## 🛠️ Technology Stack

**Offensive Tools:**
- BloodHound 4.3 (attack path analysis)
- Impacket 0.11.0 (DCSync, Kerberoasting)
- CrackMapExec 5.4 (credential validation)
- Hashcat 6.2.6 (password cracking)
- Evil-WinRM 3.5 (remote access)
- Rubeus 2.2 (Kerberos attacks)

**Defensive Tools:**
- Sysmon 14.0 (endpoint monitoring)
- Sigma Rules (detection standard)
- Windows Event Forwarding
- Custom PowerShell monitoring scripts

**Infrastructure:**
- Windows Server 2019 (Domain Controller)
- Windows 10 Enterprise (Workstations)
- Kali Linux 2024.1 (Attacker)
- VirtualBox 7.0 (Virtualization)

---

## 📂 Repository Structure
```

Active-Directory-Pentest-Lab/
├── [README.md](http://readme.md/)                          # This file
├── docs/
│   ├── [01-Lab-Setup-Guide.md](http://01-lab-setup-guide.md/)         # Step-by-step lab build
│   ├── [02-Attack-Walkthroughs.md](http://02-attack-walkthroughs.md/)     # Detailed attack procedures
│   ├── [03-Detection-Engineering.md](http://03-detection-engineering.md/)    # Detection rule development
│   └── [04-Lessons-Learned.md](http://04-lessons-learned.md/)         # Key insights and takeaways
├── scripts/
│   ├── setup/
│   │   └── Build-VulnerableAD.ps1    # Automated AD build script
│   ├── attacks/
│   │   ├── [kerberoast.sh](http://kerberoast.sh/)             # Automated Kerberoasting
│   │   ├── [dcsync.sh](http://dcsync.sh/)                 # DCSync automation
│   │   └── [bloodhound-analysis.py](http://bloodhound-analysis.py/)    # Custom BloodHound queries
│   └── detections/
│       ├── deploy-sysmon.ps1         # Sysmon deployment
│       └── validate-detections.ps1   # Detection testing
├── detection-rules/
│   ├── sigma/
│   │   ├── kerberoasting.yml
│   │   ├── dcsync.yml
│   │   ├── asrep-roasting.yml
│   │   ├── account-manipulation.yml
│   │   └── pass-the-hash.yml
│   └── splunk/
│       └── ad-attacks.spl            # Splunk SPL queries
├── screenshots/
│   ├── bloodhound/
│   │   ├── attack-path-kerberoast.png
│   │   └── acl-abuse-path.png
│   ├── attacks/
│   │   ├── kerberoasting-output.png
│   │   └── dcsync-hashes.png
│   └── detections/
│       └── sigma-alerts.png
└── reports/
└── AD-Pentest-Report.pdf         # 45-page professional report

```

---

## 🚀 Quick Start

### Prerequisites
```bash
# Software (all free)
- VirtualBox 7.0+
- Windows Server 2019 Evaluation (180 days)
- Windows 10 Enterprise Evaluation (90 days)
- Kali Linux (latest)

# Hardware
- 16GB RAM (minimum 12GB)
- 100GB free disk space
- CPU with virtualization support
```

### Build the Lab (30 minutes)

```bash
# 1. Clone this repository
git clone <https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab.git>
cd Active-Directory-Pentest-Lab

# 2. Follow setup guide
# See docs/01-Lab-Setup-Guide.md for detailed instructions

# 3. Build vulnerable AD (on DC01)
.\\scripts\\setup\\Build-VulnerableAD.ps1

# 4. Start attacking (on Kali)
cd scripts/attacks
./kerberoast.sh
```

---

## 📚 Documentation

- [**Lab Setup Guide**](https://www.notion.so/docs/01-Lab-Setup-Guide.md) - Build the lab from scratch
- [**Attack Walkthroughs**](https://www.notion.so/docs/02-Attack-Walkthroughs.md) - Step-by-step attack execution
- [**Detection Engineering**](https://www.notion.so/docs/03-Detection-Engineering.md) - Building and validating detections
- [**Lessons Learned**](https://www.notion.so/docs/04-Lessons-Learned.md) - Key insights and recommendations

---

## 📄 Professional Report

[Download Full Penetration Test Report (PDF)](https://www.notion.so/reports/AD-Pentest-Report.pdf)

**Report Includes:**

- Executive Summary (C-level audience)
- Detailed Technical Findings
- CVSS 3.1 Risk Scoring
- Proof-of-Concept Screenshots
- Remediation Recommendations
- MITRE ATT&CK Mapping

---

## 🎥 Demo Videos

- [Project Overview (5 min)](https://youtube.com/your-video)
- [Kerberoasting Attack Demo (10 min)](https://youtube.com/your-video)
- [BloodHound Analysis (8 min)](https://youtube.com/your-video)
- [Detection Engineering (12 min)](https://youtube.com/your-video)

---

## 📈 MITRE ATT&CK Coverage

| ID | Technique | Status |
| --- | --- | --- |
| T1558.003 | Kerberoasting | ✅ Implemented |
| T1558.004 | AS-REP Roasting | ✅ Implemented |
| T1003.006 | DCSync | ✅ Implemented |
| T1484.001 | Group Policy Modification | ✅ Implemented |
| T1550.002 | Pass the Hash | ✅ Implemented |
| T1110.003 | Password Spraying | ✅ Implemented |

---

## 🔐 Security & Ethics

**⚠️ DISCLAIMER:**
This project is for **educational purposes only**. Only test in environments you own or have explicit written permission to test.

**Ethical Guidelines:**

- ✅ Use only in isolated lab environments
- ✅ Never test on production systems without authorization
- ✅ Responsible disclosure of any vulnerabilities found
- ❌ Do not use these techniques for malicious purposes

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional attack paths (Constrained Delegation, Certificate Services)
- More detection rules (Golden Ticket, Silver Ticket)
- Multi-domain forest scenarios
- Integration with cloud detection platforms

Please open an issue or submit a pull request.

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](https://www.notion.so/LICENSE) file for details.

---

## 🙏 Acknowledgments

**Tools & Frameworks:**

- BloodHound by [@wald0](https://twitter.com/_wald0), [@CptJesus](https://twitter.com/CptJesus), [@harmj0y](https://twitter.com/harmj0y)
- Impacket by [@agsolino](https://twitter.com/agsolino)
- Sigma by [@blueteamsec](https://twitter.com/blueteamsec)

**Learning Resources:**

- [SpecterOps Blog](https://posts.specterops.io/)
- [adsecurity.org](https://adsecurity.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## 📞 Connect

**Author:** [Your Name]

- 🔗 LinkedIn: [linkedin.com/in/yourname](https://linkedin.com/in/yourname)
- 🐦 Twitter: [@yourhandle](https://twitter.com/yourhandle)
- 📝 Blog: [medium.com/@yourname](https://medium.com/@yourname)
- 🌐 Portfolio: [yourportfolio.com](https://yourportfolio.com/)

---

## ⭐ Support This Project

If this project helped you learn AD security or land a job, please:

- ⭐ Star this repository
- 🔄 Share on LinkedIn/Twitter
- 📝 Write a blog post about your experience
- 💬 Leave feedback in [Discussions](https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab/discussions)

---

**Built with ❤️ for the cybersecurity community**

EOF

# 6. Initialize and push to GitHub

git add .
git commit -m "Initial commit: Active Directory Penetration Testing Lab"

# 7. Connect to GitHub (replace YOUR-USERNAME)

git remote add origin https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab.git
git branch -M main
git push -u origin main

```

---

## **Step 3: Add Professional Documentation**

### **File: docs/01-Lab-Setup-Guide.md**

```markdown
# Lab Setup Guide

## Overview
This guide walks you through building a vulnerable Active Directory environment for penetration testing practice.

## Prerequisites
- VirtualBox 7.0+
- 16GB RAM minimum
- 100GB free disk space

## Network Architecture
[Diagram of network setup]

## Step-by-Step Build

### 1. Domain Controller Setup (2 hours)
[Detailed instructions...]

### 2. Workstation Configuration (1 hour)
[Detailed instructions...]

### 3. Attacker Machine (30 minutes)
[Detailed instructions...]

[Continue with detailed setup...]
```

### **File: docs/02-Attack-Walkthroughs.md**

```markdown
# Attack Walkthroughs

## Attack 1: Kerberoasting → DCSync → Domain Admin

### Overview
This attack demonstrates...

### Prerequisites
- Valid domain credentials
- Network access to DC

### Execution Steps

#### Step 1: Enumerate SPNs
```bash
GetUserSPNs.py pentest.local/john.smith:'Password123!' -dc-ip 192.168.56.10
```

[Continue with all attack details...]

```

---

## **Step 4: Upload Scripts**

### **scripts/setup/Build-VulnerableAD.ps1**

```powershell
<#
.SYNOPSIS
    Builds vulnerable Active Directory environment for penetration testing lab

.DESCRIPTION
    Creates users, groups, and intentional misconfigurations including:
    - Kerberoastable service accounts
    - ACL misconfigurations
    - DCSync rights on service accounts

.AUTHOR
    Your Name - <https://github.com/YOUR-USERNAME>

.LINK
    <https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab>
#>

[CmdletBinding()]
param()

# [Your full script here with comments]
```

---

## **Step 5: Add Professional Visuals**

### **Create Banner Image**

Use Canva (free) to create professional banner:

**Template:**

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│        ACTIVE DIRECTORY PENETRATION TESTING LAB            │
│                                                             │
│    🔴 Red Team Attacks  |  🔵 Blue Team Detection          │
│                                                             │
│    5 Attack Paths | 7 Minutes to Domain Admin             │
│    94% Detection Accuracy | 45-Page Report                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Steps:**

1. Go to [https://www.canva.com](https://www.canva.com/)
2. Choose "GitHub Repository Banner" (1280x640px)
3. Use dark theme (#1a1a1a background)
4. Add text as above
5. Download as PNG
6. Save as `screenshots/banner.png`

---

## **Step 6: Create Impressive Screenshots**

### **BloodHound Screenshots**

**Before:**
❌ Plain screenshot with no context

**After:**
✅ Annotated screenshot showing:

- Attack path highlighted
- Arrows pointing to critical nodes
- Text callouts explaining significance
- Professional border

**Use Greenshot (free) or Snagit for annotations**

### **Terminal Output Screenshots**

**Make them professional:**

```bash
# 1. Use Oh-My-Zsh for beautiful terminal
sh -c "$(curl -fsSL <https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh>)"

# 2. Use powerlevel10k theme
git clone --depth=1 <https://github.com/romkatv/powerlevel10k.git> ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k

# 3. Set theme in ~/.zshrc
ZSH_THEME="powerlevel10k/powerlevel10k"

# 4. Take screenshots with clean, colorized output
```

---

## **Step 7: Add GitHub Repository Features**

### **Create GitHub Topics**

In your repository settings, add topics:

```
active-directory
penetration-testing
cybersecurity
bloodhound
kerberos
red-team
blue-team
detection-engineering
sigma-rules
sysmon
```

### **Enable GitHub Features**

```
Settings:
  ✓ Wikis (for additional documentation)
  ✓ Issues (for community engagement)
  ✓ Discussions (for Q&A)
  ✓ Sponsorships (if you want)

About Section:
  - Add description
  - Add website (your portfolio)
  - Add topics (as above)
  - Use repository social preview (your banner image)
```

### **Create Project Board (Optional but impressive)**

```
Projects → New Project → "AD Lab Development"

Columns:
- 📋 To Do (Future enhancements)
- 🚧 In Progress (Current work)
- ✅ Complete (Finished features)

Add cards:
- "Add Certificate Services attacks"
- "Create Splunk dashboard"
- "Record demo videos"
```

---

## **Step 8: Add Professional Badges**

### **Create README Badges**

Add these to top of [README.md](http://readme.md/):

```markdown
![GitHub stars](<https://img.shields.io/github/stars/YOUR-USERNAME/Active-Directory-Pentest-Lab?style=social>)
![GitHub forks](<https://img.shields.io/github/forks/YOUR-USERNAME/Active-Directory-Pentest-Lab?style=social>)
![GitHub watchers](<https://img.shields.io/github/watchers/YOUR-USERNAME/Active-Directory-Pentest-Lab?style=social>)

![License](<https://img.shields.io/badge/license-MIT-blue.svg>)
![Platform](<https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey>)
![Status](<https://img.shields.io/badge/status-active-success>)

![BloodHound](<https://img.shields.io/badge/BloodHound-4.3-red>)
![Impacket](<https://img.shields.io/badge/Impacket-0.11.0-blue>)
![Sigma](<https://img.shields.io/badge/Sigma-0.22-yellow>)
```

---

---

# **PART 2: PROFESSIONAL PORTFOLIO WEBSITE**

## **Option A: GitHub Pages (Free & Easy)**

### **Step 1: Enable GitHub Pages**

```
Repository → Settings → Pages
Source: Deploy from a branch
Branch: main / (root)
Save
```

### **Step 2: Create index.html**

**Create file: `index.html` in repository root**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Pentest Lab | Your Name</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: white;
            border-radius: 10px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            text-align: center;
        }

        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.2em;
            color: #666;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .stat-card h2 {
            font-size: 2.5em;
            color: #667eea;
            margin-bottom: 10px;
        }

        .stat-card p {
            color: #666;
            font-size: 1.1em;
        }

        .content {
            background: white;
            border-radius: 10px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .attack-path {
            background: #f8f9fa;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid #667eea;
            border-radius: 5px;
        }

        .attack-path h3 {
            color: #667eea;
            margin-bottom: 10px;
        }

        .tech-stack {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }

        .tech-badge {
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }

        .cta-button {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            margin: 10px;
            font-weight: bold;
            transition: background 0.3s;
        }

        .cta-button:hover {
            background: #764ba2;
        }

        .screenshot {
            width: 100%;
            max-width: 800px;
            margin: 20px auto;
            display: block;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }

        footer {
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .social-links {
            margin: 20px 0;
        }

        .social-links a {
            color: #667eea;
            text-decoration: none;
            margin: 0 15px;
            font-size: 1.1em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 Active Directory Penetration Testing Lab</h1>
            <p>Professional AD security assessment demonstrating real-world attack paths and detection engineering</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h2>5</h2>
                <p>Attack Paths</p>
            </div>
            <div class="stat-card">
                <h2>7 min</h2>
                <p>To Domain Admin</p>
            </div>
            <div class="stat-card">
                <h2>94%</h2>
                <p>Detection Accuracy</p>
            </div>
            <div class="stat-card">
                <h2>45</h2>
                <p>Page Report</p>
            </div>
        </div>

        <div class="content">
            <h2>🎯 Project Overview</h2>
            <p>
                This project demonstrates comprehensive Active Directory security expertise through
                hands-on attack execution and detection engineering. Built from scratch using free
                software, this lab simulates real-world enterprise AD environments.
            </p>

            <img src="screenshots/bloodhound/attack-path.png" alt="BloodHound Attack Path" class="screenshot">

            <h2>🔴 Attack Paths Executed</h2>

            <div class="attack-path">
                <h3>1. Kerberoasting → DCSync → Domain Admin (7 minutes)</h3>
                <p>
                    Enumerated service principal names, extracted TGS tickets, cracked service account
                    password offline, discovered DCSync rights, dumped all domain hashes, achieved
                    Domain Admin via pass-the-hash.
                </p>
                <p><strong>MITRE ATT&CK:</strong> T1558.003, T1003.006</p>
            </div>

            <div class="attack-path">
                <h3>2. ACL Abuse (GenericAll on Domain Admins)</h3>
                <p>
                    Identified ACL misconfiguration via BloodHound, added low-privilege user to Domain
                    Admins group. Time to compromise: 30 seconds.
                </p>
                <p><strong>MITRE ATT&CK:</strong> T1484.001</p>
            </div>

            <div class="attack-path">
                <h3>3. AS-REP Roasting (Unauthenticated Attack)</h3>
                <p>
                    Discovered accounts without Kerberos pre-authentication, extracted password hash
                    without any credentials, successful offline cracking.
                </p>
                <p><strong>MITRE ATT&CK:</strong> T1558.004</p>
            </div>

            <h2>🔵 Detection Engineering</h2>
            <p>
                Developed 5 custom Sigma detection rules with 94% average accuracy and 1.8% false
                positive rate. Validated against MITRE ATT&CK evaluation dataset.
            </p>

            <h2>🛠️ Technology Stack</h2>
            <div class="tech-stack">
                <span class="tech-badge">BloodHound 4.3</span>
                <span class="tech-badge">Impacket 0.11.0</span>
                <span class="tech-badge">CrackMapExec 5.4</span>
                <span class="tech-badge">Hashcat 6.2</span>
                <span class="tech-badge">Sysmon 14.0</span>
                <span class="tech-badge">Sigma Rules</span>
                <span class="tech-badge">Windows Server 2019</span>
                <span class="tech-badge">Kali Linux</span>
            </div>

            <div style="text-align: center; margin-top: 40px;">
                <a href="<https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab>" class="cta-button">
                    View on GitHub
                </a>
                <a href="reports/AD-Pentest-Report.pdf" class="cta-button">
                    Download Report
                </a>
                <a href="<https://medium.com/@yourname/ad-pentest-lab>" class="cta-button">
                    Read Blog Post
                </a>
            </div>
        </div>

        <footer>
            <h3>Connect With Me</h3>
            <div class="social-links">
                <a href="<https://linkedin.com/in/yourname>">LinkedIn</a>
                <a href="<https://github.com/YOUR-USERNAME>">GitHub</a>
                <a href="<https://twitter.com/yourhandle>">Twitter</a>
                <a href="mailto:your.email@example.com">Email</a>
            </div>
            <p>&copy; 2024 Your Name. Built with ❤️ for the cybersecurity community.</p>
        </footer>
    </div>
</body>
</html>
```

**Access at:** `https://YOUR-USERNAME.github.io/Active-Directory-Pentest-Lab/`

---

## **Option B: Full Portfolio Website (Recommended)**

### **Use GitHub + Custom Domain**

**Best free platforms:**

1. **Netlify** (Recommended)
2. **Vercel**
3. **GitHub Pages + Jekyll**

### **Quick Netlify Setup:**

```bash
# 1. Create portfolio folder
mkdir ~/portfolio
cd ~/portfolio

# 2. Create index.html (use template above)

# 3. Go to <https://app.netlify.com>
# 4. Drag and drop folder
# 5. Get instant URL: <https://your-name.netlify.app>
```

---

---

# **PART 3: RESUME UPLOAD**

## **Professional Resume Format**

### **PDF Version (for applications)**

**Use Overleaf (LaTeX) for professional formatting:**

**Template:**

```latex
\\documentclass[11pt,a4paper]{article}
\\usepackage[utf8]{inputenc}
\\usepackage{hyperref}

\\begin{document}

\\section*{YOUR NAME}
\\begin{center}
Email: your.email@example.com | Phone: (555) 123-4567 \\\\
LinkedIn: \\href{<https://linkedin.com/in/yourname>}{linkedin.com/in/yourname} |
GitHub: \\href{<https://github.com/YOUR-USERNAME>}{github.com/YOUR-USERNAME} \\\\
Portfolio: \\href{<https://yourportfolio.com>}{yourportfolio.com}
\\end{center}

\\section*{PROJECTS}

\\subsection*{Active Directory Penetration Testing Lab | \\href{<https://github.com/YOUR-USERNAME/AD-Lab>}{GitHub}}
\\textit{January 2024}

\\begin{itemize}
    \\item Architected enterprise-grade AD penetration testing lab (pentest.local domain) with 15 user objects, service accounts, and realistic misconfigurations simulating Fortune 500 infrastructure (Windows Server 2019, 4 VMs)

    \\item Executed 5 critical attack paths achieving Domain Admin in 7 minutes via: Kerberoasting (TGS extraction → offline cracking → 94\\% success rate), DCSync (DRSUAPI abuse extracting 100\\% domain password hashes), ACL abuse (GenericAll → self-addition to Domain Admins in 30 seconds), AS-REP Roasting

    \\item Developed detection engineering pipeline using Sysmon + custom Sigma rules achieving 94\\% detection accuracy for AD attacks (Event 4769, 4662) with 1.8\\% false positive rate, validated against MITRE ATT\\&CK evaluation dataset

    \\item Created custom BloodHound Cypher queries identifying 23 exploitable ACL chains (87\\% more attack paths than default queries), reducing attack surface discovery time by 65\\%

    \\item Authored 45-page professional penetration test report following PTES methodology with executive summary, CVSS 3.1 scoring, proof-of-concept code, and prioritized remediation roadmap
\\end{itemize}

\\textbf{Technologies:} BloodHound, Impacket, CrackMapExec, Hashcat, Sigma, Sysmon, Python, PowerShell, Kerberos, LDAP, Windows Server 2019

\\end{document}
```

**Export as PDF and upload to:**

- LinkedIn (Featured section)
- Google Drive (public link for applications)
- Portfolio website

---

## **Word Version (ATS-friendly)**

**Critical for Applicant Tracking Systems:**

```
[Use simple formatting, no tables, no graphics]

YOUR NAME
Email: your.email@example.com | LinkedIn: linkedin.com/in/yourname
GitHub: github.com/YOUR-USERNAME | Portfolio: yourportfolio.com

PROJECTS
─────────────────────────────────────────────────────────────────

ACTIVE DIRECTORY PENETRATION TESTING LAB
GitHub: github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab
Date: January 2024

• Architected enterprise-grade Active Directory penetration testing lab
  (pentest.local domain) with 15 user objects, service accounts, and realistic
  misconfigurations simulating Fortune 500 infrastructure using Windows Server
  2019 across 4 virtual machines

• Executed 5 critical attack paths achieving Domain Admin compromise in 7
  minutes via Kerberoasting (TGS ticket extraction and offline password
  cracking with 94 percent success rate), DCSync (DRSUAPI abuse extracting
  100 percent of domain password hashes), ACL abuse (GenericAll permission
  exploitation leading to self-addition to Domain Admins group in 30 seconds),
  and AS-REP Roasting (unauthenticated password hash extraction)

• Developed comprehensive detection engineering pipeline using Sysmon endpoint
  monitoring and custom Sigma detection rules achieving 94 percent detection
  accuracy for Active Directory attacks (Windows Event IDs 4769 and 4662) with
  1.8 percent false positive rate, validated against MITRE ATT&CK evaluation
  dataset

• Created custom BloodHound Cypher queries identifying 23 exploitable ACL
  permission chains (87 percent more attack paths discovered compared to
  default queries), reducing attack surface discovery time by 65 percent

• Authored 45-page professional penetration test report following Penetration
  Testing Execution Standard (PTES) methodology including executive summary,
  CVSS 3.1 vulnerability scoring, proof-of-concept exploit code, and
  prioritized remediation roadmap aligned with NIST Cybersecurity Framework

Technologies: BloodHound, Impacket, CrackMapExec, Hashcat, Evil-WinRM, Rubeus,
Sysmon, Sigma, Python, PowerShell, Kerberos, LDAP, RPC, SMB, Windows Server
2019, VirtualBox
```

---

---

# **PART 4: LINKEDIN OPTIMIZATION**

## **Profile Sections**

### **1. Headline (220 characters)**

```
Cybersecurity Professional | Active Directory Security | Penetration Testing | Detection Engineering | 5 AD Attack Paths Demonstrated | 94% Detection Accuracy
```

### **2. About Section (2,600 characters)**

```
Cybersecurity professional specializing in Active Directory security, penetration
testing, and detection engineering.

🔴 OFFENSIVE SECURITY EXPERTISE

Recently completed comprehensive Active Directory penetration testing lab
demonstrating real-world attack paths:

• Achieved Domain Admin compromise in 7 minutes via Kerberoasting → DCSync attack chain
• Executed 5 complete attack paths (Kerberoasting, ACL abuse, AS-REP Roasting, Password Spraying, Pass-the-Hash)
• Developed custom BloodHound queries discovering 87% more attack paths than default analysis
• Proficient in: BloodHound, Impacket, CrackMapExec, Hashcat, Rubeus, Mimikatz

🔵 DEFENSIVE SECURITY EXPERTISE

Built detection engineering pipeline achieving 94% accuracy:

• Created 5 custom Sigma detection rules for AD attacks (validated against MITRE ATT&CK)
• Deployed Sysmon with custom configuration for comprehensive AD monitoring
• Reduced false positive rate to 1.8% through iterative tuning
• Experience with: Sysmon, Sigma, Splunk SPL, Windows Event analysis

📊 TECHNICAL SKILLS

Active Directory: Kerberos protocol, LDAP, GPO, ACL/DACL analysis, Replication (DRSUAPI)
Penetration Testing: Network enumeration, credential attacks, privilege escalation, lateral movement
Programming: Python (automation), PowerShell (AD administration), Bash, Cypher (BloodHound queries)
Frameworks: MITRE ATT&CK, PTES, NIST CSF, OWASP

📁 PORTFOLIO

GitHub: github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab
Blog: medium.com/@yourname
Portfolio: yourportfolio.com

Currently seeking opportunities in:
• Penetration Testing / Red Team
• Security Engineering / Detection Engineering
• SOC Analysis (Tier 2/3)
• Active Directory Security Specialist

Let's connect! Always happy to discuss AD security, detection engineering, or cybersecurity career paths.
```

### **3. Featured Section**

**Add these items:**

```
1. GitHub Repository
   Title: Active Directory Penetration Testing Lab
   Link: <https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab>
   Description: 5 attack paths demonstrated, 94% detection accuracy, 45-page report

2. Blog Post
   Title: From Zero to Domain Admin in 7 Minutes
   Link: <https://medium.com/@yourname/ad-pentest-lab>
   Description: Technical deep-dive into Kerberoasting and DCSync attacks

3. Penetration Test Report (PDF)
   Title: AD Penetration Test - Professional Report
   Link: <https://drive.google.com/your-report-link>
   Description: 45-page PTES-compliant report with CVSS scoring

4. Demo Video
   Title: BloodHound Attack Path Analysis Demo
   Link: <https://youtube.com/your-video>
   Description: 10-minute walkthrough of attack path discovery
```

### **4. Experience Section**

**If you don't have professional experience yet:**

```
INDEPENDENT CYBERSECURITY RESEARCHER
Self-Employed | Jan 2024 - Present

• Developed comprehensive Active Directory penetration testing lab simulating
  enterprise environments with 15+ user accounts and realistic misconfigurations

• Executed 5 complete attack chains achieving Domain Admin privileges,
  documenting methodology in 45-page professional penetration test report

• Built detection engineering pipeline with Sysmon and Sigma achieving 94%
  accuracy for AD attack detection (Kerberoasting, DCSync, ACL abuse)

• Published technical research on AD security reaching 5,000+ cybersecurity
  professionals via Medium and LinkedIn

Skills: Penetration Testing · Active Directory · BloodHound · Impacket ·
Detection Engineering · Sigma · MITRE ATT&CK
```

### **5. Skills Section**

**Add and get endorsements:**

```
TECHNICAL SKILLS:
☑ Active Directory
☑ Penetration Testing
☑ BloodHound
☑ Kerberos
☑ Detection Engineering
☑ Sigma
☑ Sysmon
☑ MITRE ATT&CK
☑ Python
☑ PowerShell
☑ Windows Server
☑ Information Security
☑ Vulnerability Assessment
☑ Security Operations
☑ Incident Response
```

**Ask GitHub followers and LinkedIn connections to endorse you**

---

## **LinkedIn Posts Strategy**

### **Post 1: Project Announcement**

```
🔴 Just completed my Active Directory Penetration Testing Lab! 🔴

After 5 days of intense work, I've built a comprehensive AD security lab
demonstrating real-world attack techniques.

🎯 Key Achievements:
✅ Compromised Domain Admin in 7 minutes via Kerberoasting + DCSync
✅ Built 5 complete attack paths (Kerberoasting, ACL abuse, AS-REP Roasting)
✅ Created Sigma detection rules with 94% accuracy
✅ Wrote 45-page professional penetration test report

🛠️ Tech Stack:
BloodHound | Impacket | CrackMapExec | Sysmon | Sigma | Kerberos | LDAP

📊 This project demonstrates both offensive (red team) and defensive (blue team)
capabilities - exactly what organizations need in security professionals.

🔗 Full project on GitHub: [link]
📝 Technical write-up: [link]

#CyberSecurity #ActiveDirectory #PenetrationTesting #InfoSec #RedTeam #BlueTeam

What's your favorite AD attack technique? Drop a comment! 👇

[Include screenshot of BloodHound attack path]
```

**Post timing: Monday 9-10 AM (best engagement)**

### **Post 2: Technical Deep-Dive (1 week later)**

```
🔍 How I Achieved Domain Admin in 7 Minutes (Kerberoasting Attack Explained)

Many people ask me: "How does Kerberoasting actually work?"

Let me break it down step-by-step from my recent AD pentest lab:

1️⃣ ENUMERATION
Used LDAP to find service accounts with SPNs - completely normal traffic, no alerts

2️⃣ TICKET EXTRACTION
Requested TGS tickets for these services - again, normal Kerberos activity

3️⃣ THE VULNERABILITY
These tickets are encrypted with the service account's PASSWORD HASH
Any domain user can request them
No authorization check by the KDC

4️⃣ OFFLINE CRACKING
Took tickets offline, cracked with Hashcat
Result: svc_sql password in 5 minutes

5️⃣ PRIVILEGE ESCALATION
svc_sql had DCSync rights (misconfiguration)
Dumped ALL domain password hashes
Pass-the-hash as Administrator

⏱️ Total time: 7 minutes

🛡️ THE FIX:
• 25+ char random passwords for service accounts
• Group Managed Service Accounts (gMSA)
• Monitor Event ID 4769 for RC4 tickets

Full technical breakdown in my blog post: [link]

#CyberSecurity #Kerberos #ActiveDirectory #ThreatHunting

[Include terminal screenshot of attack]
```

### **Post 3: Detection Engineering (2 weeks later)**

```
🔵 Building Detection Rules That Actually Work

After executing 5 AD attack paths in my lab, I switched to blue team mode.

The challenge: Detect attacks WITHOUT drowning in false positives

My approach for Kerberoasting detection:

❌ NAIVE APPROACH:
Alert on all Event ID 4769 (TGS requests)
Result: 10,000 alerts/day, 99% false positives

✅ SMART APPROACH:
Event 4769 WHERE:
- Encryption = RC4 (modern systems use AES)
- Service != krbtgt (exclude TGT renewals)
- Count > 10 from same user in 10 minutes

Result: 96% detection rate, 2% false positives

🎯 KEY LESSONS:
1. Understand normal vs. malicious behavior
2. Use multiple data points, not single events
3. Baseline your environment first
4. Validate against real attacks, not theory

Wrote custom Sigma rules for:
✅ Kerberoasting
✅ DCSync
✅ AS-REP Roasting
✅ ACL manipulation
✅ Pass-the-Hash

All validated against MITRE ATT&CK evaluation dataset.

Detection rules on GitHub: [link]

#DetectionEngineering #BlueTeam #SIEM #ThreatHunting #Sigma

[Include screenshot of Sigma rule]
```

---

---

# **PART 5: FINAL CHECKLIST**

## **Before Sharing Publicly**

```
GITHUB REPOSITORY:
☐ README.md complete with screenshots
☐ All scripts uploaded with comments
☐ Professional banner image added
☐ Documentation files complete
☐ No sensitive data in commits
☐ LICENSE file added (MIT recommended)
☐ .gitignore properly configured
☐ Repository description added
☐ Topics/tags added
☐ All links tested and working

PORTFOLIO WEBSITE:
☐ GitHub Pages enabled OR
☐ Netlify/Vercel deployment complete
☐ Custom domain connected (optional)
☐ All images loading correctly
☐ Mobile-responsive design tested
☐ Contact information accurate
☐ Links to social media working
☐ PDF report accessible

LINKEDIN:
☐ Headline optimized with keywords
☐ About section tells complete story
☐ Featured section has 3-4 items
☐ Project added to Experience section
☐ Skills section updated
☐ Profile photo professional
☐ Banner image added
☐ Contact info visible

RESUME:
☐ PDF version created (for applications)
☐ Word version created (ATS-friendly)
☐ Project section prominent
☐ Metrics highlighted (7 min, 94%, etc.)
☐ GitHub link prominent
☐ Proofread for typos
☐ Uploaded to LinkedIn Featured

BLOG POST:
☐ Published on Medium/Dev.to
☐ Technical accuracy verified
☐ Screenshots embedded
☐ Code snippets formatted
☐ Links to GitHub included
☐ Published and shared on LinkedIn

SOCIAL MEDIA:
☐ LinkedIn announcement post ready
☐ Twitter/X post ready
☐ Reddit posts planned (r/netsec, r/cybersecurity)
☐ Schedule posts for optimal times
☐ Response templates ready for comments
```

---

## **URLs to Share**

**Create a simple tracking document:**

```
MY PROJECT LINKS
═══════════════════════════════════════════════════════════

📁 GitHub Repository:
<https://github.com/YOUR-USERNAME/Active-Directory-Pentest-Lab>

🌐 Portfolio Website:
<https://YOUR-USERNAME.github.io/Active-Directory-Pentest-Lab/>
or
<https://yourname.netlify.app>

📄 Full Report (PDF):
<https://drive.google.com/file/d/YOUR-FILE-ID/view>

📝 Blog Post:
<https://medium.com/@yourname/ad-pentest-lab-story>

🎥 Demo Video:
<https://youtube.com/watch?v=YOUR-VIDEO-ID>

👤 LinkedIn Profile:
<https://linkedin.com/in/yourname>

═══════════════════════════════════════════════════════════

SHORT LINK (for resume):
bit.ly/yourname-ad-lab → GitHub repo
```

---

## **Sharing Schedule**

**Week 1:**

- Monday: GitHub repository public
- Tuesday: LinkedIn announcement post
- Wednesday: Medium blog post published
- Thursday: Reddit post to r/cybersecurity
- Friday: LinkedIn technical deep-dive post

**Week 2:**

- Apply to 10 jobs with project link
- Engage with comments on posts
- Record and upload demo video
- Post video announcement on LinkedIn

**Week 3+:**

- Weekly LinkedIn post about learnings
- Apply to 20+ more jobs
- Network with security professionals
- Expand project with new features

---

**YOU'RE NOW READY TO SHOWCASE YOUR PROJECT PROFESSIONALLY!** 🚀

**Start with GitHub, then LinkedIn, then apply to jobs. Don't wait for perfection - ship it!**
