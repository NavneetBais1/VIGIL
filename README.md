```markdown
<div align="center">

```text
 __      __ _____   ____  _____  _      
 \ \    / /|_   _| / ___||_   _|| |     
  \ \  / /   | |  | |  _   | |  | |     
   \ \/ /   _| |_ | |_| | _| |_ | |___  
    \__/   |_____| \____||_____||_____| 

```

### **Autonomous AI-Driven Threat Detection & Post-Quantum Cryptographic Vault**

---

## 🛡️ Core Capabilities

| Module | Core Technology | Function | Key Feature |
| --- | --- | --- | --- |
| **AI IDS Engine** | Scapy + `IsolationForest` | Live anomaly classification | Shannon payload entropy scoring & SYN flood tracking |
| **Post-Quantum Vault** | SHA3-512 HKDF + AES-256-GCM | Ephemeral hybrid encryption | Zero-leak execution via default OS application |
| **Access Sentry** | PBKDF2 / Salted Hashing | Authentication & lockout guard | 3-Strike failover to case/space-agnostic recovery questions |
| **System Sanity** | Local Session Isolation | Zero-artifact wiping | Dedicated authenticated master reset engine |

---

## ⚡ System Architecture

```text
                                  ┌────────────────────────┐
                                  │      VIGIL CORE        │
                                  └───────────┬────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
      ┌─────────────────────────────┐                   ┌─────────────────────────────┐
      │   AI IDS DETECTION ENGINE   │                   │  POST-QUANTUM HYBRID VAULT  │
      └──────────────┬──────────────┘                   └──────────────┬──────────────┘
                     │                                                 │
        ┌────────────┴────────────┐                       ┌────────────┴────────────┐
        ▼                         ▼                       ▼                         ▼
 ┌──────────────┐          ┌──────────────┐        ┌──────────────┐          ┌──────────────┐
 │ Scapy Sniff  │          │ Isolation    │        │ SHA3-512 KDF │          │ Ephemeral    │
 │ (Raw Sockets)│          │ Forest Anom. │        │ + AES-256-GCM│          │ Decrypt/Open │
 └──────────────┘          └──────────────┘        └──────────────┘          └──────────────┘

```

---

## 🖥️ User Interface Overview

* **OLED Pitch-Black Design (`#000000`):** Contoured with 1px structural white dividers and pure teal (`#00f0c0`) hover telemetry.
* **Vector Animated Eye Elements:** Trailing eye glyphs rendered via `QPainter` line paths with sub-pixel easing curves that track input visibility states.
* **Live Telemetry Stream:** Dual-buffered event feed differentiating safe transactions (`#00f0c0`) from threat signatures (`#ff3366`).

---

## 🗂️ Project Structure

```text
vigil_security_suite/
├── .gitignore               # Strict exclusion matrix for configs and caches
├── requirements.txt         # Production dependency manifest
├── main.py                  # Process bootstrap & window routing
│
├── core/
│   ├── __init__.py
│   ├── ai_ids_engine.py     # Packet sniffer & unsupervised ML isolation classifier
│   ├── auth_manager.py      # Dynamic credential manager & salted digest validation
│   └── pq_crypto.py         # Post-Quantum envelope cryptor & launcher
│
└── ui/
    ├── __init__.py
    ├── auth_dialog.py       # Modal lockscreen with embedded vector eye switches
    ├── ids_view.py          # Threat telemetry canvas and heuristic toggles
    ├── settings_dialog.py   # In-place credential rotation & authorized reset modal
    ├── styles.py            # Global OLED stylesheet definitions (QSS)
    └── vault_view.py        # Explicit file selection and processing pane

```

---

## 🚀 Getting Started

### 1. Prerequisites

* **Python 3.10 or higher**
* **Windows Users:** Install [Npcap](https://www.google.com/search?q=https://npcap.com/) with **"Install Npcap in WinPcap API-compatible Mode"** enabled for packet capture.
* **Linux Users:** Ensure raw socket access capabilities are granted to Python, or run with administrative privileges (`sudo`).

### 2. Clone the Repository

```bash
git clone [https://github.com/NavneetBais1/VIGIL.git](https://github.com/NavneetBais1/VIGIL.git)
cd VIGIL

```

### 3. Setup Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate

```

### 4. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt

```

### 5. Launch the Application

```bash
python main.py

```

---

## ⚙️ Operating Instructions

```text
[ Step 01: Setup ] ──> [ Step 02: IDS Monitoring ] ──> [ Step 03: File Encryption ]

```

### 1. First-Time Initialization

1. Upon your first launch, Vigil detects the absence of any localized profile and presents the **Create Master Security Profile** screen.
2. Provide a **Master Password** and configure a **Personal Security Question & Answer**.
3. *Note:* Answers to recovery challenges are normalized at runtime—spaces, symbols, and letter casing are stripped during evaluation.

### 2. Running the Intrusion Detection System

1. Select the **AI Intrusion Detection** panel from the sidebar.
2. Toggle the detection sub-vectors according to your preference:
* **Port Scan Detection** (Flags coordinated horizontal port traversal)
* **SYN Flood / DoS** (Flags anomalous half-open TCP states)
* **Payload Entropy** (Inspects payload byte randomness for obfuscated C2 traffic)
* **AI ML Anomaly Classifier** (Evaluates outlier boundaries via `IsolationForest`)


3. Click **Enable IDS Engine** to begin live monitoring.

### 3. Encrypting & Opening Files

1. Select **Post-Quantum Vault** from the sidebar.
2. Click **➕ Select Target File** to pick a specific `.txt` or `.csv` document. *(Vigil never scans or indexes directories autonomously).*
3. Supply an encryption key and choose:
* **Encrypt File:** Converts the document into a `.vigil` archive using SHA3-512 HKDF and AES-256-GCM.
* **Decrypt & Open:** Authenticates and unpacks the target into a transient memory partition, launching it directly into your OS default viewer.



---

## 🔒 Security Baseline

| Vector | Strategy |
| --- | --- |
| **Credential Persistence** | Passwords and recovery keys are never written in plaintext. All records reside in local configuration files masked with per-user cryptographic salts. |
| **Brute-Force Countermeasure** | Standard inputs are limited to 3 attempts. Exceeding thresholds initiates failover mode targeting space/case-normalized challenge questions. |
| **Version Control Hygiene** | The provided `.gitignore` prevents local configuration states (`config.json`), ephemeral vaults (`*.vigil`), decrypted caches, and Python bytecode (`__pycache__`) from leaking to remotes. |

---

## 📜 License

Distributed under the **MIT License**.

```

```
