<div align="center">

# 🛡️ VIGIL

### **AI Security Suite for Windows**

**Monitor. Detect. Protect. Encrypt.**

A desktop cybersecurity application combining **real-time intrusion detection** with a **post-quantum secure file vault**, wrapped in a modern dark desktop interface.

<br>

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-PyQt6-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Security](https://img.shields.io/badge/security-focused-111111?style=for-the-badge&logo=shield&logoColor=white)

</div>

---

## ✨ What is Vigil?

**Vigil** is a Windows desktop security suite designed to bring several practical security capabilities into one interface.

It currently provides two main security modules:

| Module | Purpose | Status |
|---|---|---|
| 🛡️ **AI Intrusion Detection** | Watches live network traffic and looks for suspicious patterns | ✅ Available |
| 🔐 **Post-Quantum File Vault** | Encrypts files using ML-KEM-768 + AES-256-GCM | ✅ Available |
| 🔑 **Authentication & Recovery** | Protects access to the Vigil application | ✅ Available |
| ⚙️ **Security Settings** | Password, recovery credentials and factory reset | ✅ Available |

> **Project status:** Vigil is a security-focused college/showcase project. It is designed to demonstrate practical cybersecurity concepts and is **not a replacement for a professionally audited endpoint security product**.

---

# 🧭 Features at a Glance

### 🛡️ AI Intrusion Detection

Vigil monitors network traffic and combines several signals instead of treating a single packet characteristic as proof of an attack.

**Detection components include:**

- 🔎 Port-scan detection
- 🌊 SYN-flood / connection-burst detection
- 📦 Suspicious payload entropy detection
- 🧠 Optional adaptive anomaly detection using `IsolationForest`
- 🚦 Alert cooldowns to reduce repeated notifications
- 🖥️ Local-network awareness
- 🧱 Optional Windows Firewall blocking response
- 📋 Human-readable security events

### 🔐 Post-Quantum File Vault

The vault uses a hybrid cryptographic design:

```text
                    ┌──────────────────────┐
                    │       FILE DATA      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    AES-256-GCM       │
                    │ Authenticated        │
                    │ Symmetric Encryption │
                    └──────────┬───────────┘
                               ▲
                               │
                         Data Encryption
                              Key
                               │
                    ┌──────────┴───────────┐
                    │       HKDF           │
                    │     SHA3-256         │
                    └──────────┬───────────┘
                               ▲
                               │
                    ┌──────────┴───────────┐
                    │      ML-KEM-768       │
                    │  Post-Quantum KEM     │
                    └───────────────────────┘
```

The implementation uses:

| Component | Role |
|---|---|
| **ML-KEM-768** | Post-quantum key encapsulation |
| **HKDF-SHA3-256** | Derives the file encryption key from the KEM shared secret |
| **AES-256-GCM** | Authenticated encryption of file contents |
| **scrypt** | Password-based protection of the ML-KEM private key |
| **Fresh salts/nonces** | Prevents reuse of encryption parameters between archives |

The vault creates `.vigil` encrypted archives.

---

# 🔒 Security Architecture

Vigil separates the security problems it is solving instead of attempting to use one primitive for everything.

```text
                         VIGIL
                           │
             ┌─────────────┴─────────────┐
             │                           │
       Application Auth             File Vault
             │                           │
          scrypt                  ML-KEM-768
             │                           │
      Master Password          HKDF-SHA3-256
             │                           │
      Recovery Credential        AES-256-GCM
```

## 🔑 Application Authentication

Vigil stores its authentication configuration outside the project directory.

The current implementation:

- Uses **scrypt** for password-derived credentials.
- Uses independent random salts for the master password and recovery answer.
- Requires a **minimum 12-character master password**.
- Stores initialization state using a per-instance Windows Registry marker.
- Uses a per-installation namespace derived from the application's location.
- Uses atomic configuration writes.
- Includes compatibility handling for older Vigil credential formats.

### Why per-instance storage?

A copied second instance of Vigil should not accidentally inherit the first instance's authentication state.

Vigil therefore derives an installation/instance identifier from its application location and stores data under an instance-specific directory.

---

# 🛡️ How the IDS Works

Vigil's IDS is intentionally **multi-signal**.

It does not claim that one unusual packet automatically means an attack.

### 1. 🔎 Port Scan Detection

Vigil maintains a short rolling activity window and looks for a remote source contacting many service ports on a local machine.

A detection can be triggered when the observed pattern reaches the configured thresholds.

### 2. 🌊 SYN Burst Detection

Vigil tracks SYN-only TCP connection attempts from remote sources.

A sustained burst can be classified as a possible SYN-flood / connection-exhaustion pattern.

### 3. 📊 Payload Entropy

Vigil can calculate Shannon entropy for sufficiently large payloads.

High entropy can occur in:

- encrypted data
- compressed data
- random-looking application data
- potentially suspicious payloads

Therefore, **entropy is treated as supporting evidence, not proof of malware**.

### 4. 🧠 Adaptive Anomaly Layer

The optional ML layer uses `IsolationForest` after collecting an initial traffic baseline.

The model is intentionally secondary:

> **The ML layer does not independently decide that an attack is occurring.**

This reduces the risk of turning generic network oddities into definitive security verdicts.

---

# 🧱 Windows Firewall Response

When the IDS identifies a supported remote threat, Vigil can provide a **Windows Firewall block action**.

Conceptually:

```text
Remote source
     │
     ▼
┌───────────────┐
│ Vigil IDS     │
│ detects       │
│ threat        │
└───────┬───────┘
        │
        ▼
┌────────────────────┐
│ User chooses block │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Windows Firewall   │
│ inbound rule       │
└────────────────────┘
```

⚠️ Firewall modification can require appropriate Windows privileges.

Vigil validates the IP address before constructing the firewall command and invokes the Windows command using argument separation rather than `shell=True`.

---

# 🔐 How File Encryption Works

Each `.vigil` archive gets its own cryptographic material.

High-level flow:

```text
                 ORIGINAL FILE
                       │
                       ▼
              Generate ML-KEM-768
                   key pair
                  /        \
                 /          \
          Public Key       Private Key
              │                │
              │                ▼
              │        Encrypt/wrap private
              │        key using password-
              │        derived AES key
              │
              ▼
       Encapsulate shared secret
              │
              ▼
        ML-KEM shared secret
              │
              ▼
          HKDF-SHA3-256
              │
              ▼
         AES-256-GCM key
              │
              ▼
        Encrypt file data
              │
              ▼
          .vigil archive
```

### Important design detail

The user's password does **not** directly become the AES file-encryption key.

Instead:

1. A fresh ML-KEM-768 key pair is generated.
2. ML-KEM produces a shared secret.
3. HKDF-SHA3-256 derives the file encryption key.
4. AES-256-GCM encrypts and authenticates the file.
5. The ML-KEM private key is separately protected using a password-derived key.
6. The archive stores the information required for later decryption.

---

# 📦 `.vigil` Archive Format

Current archives use:

```text
VIGIL_PQ_V3
```

The archive contains the cryptographic metadata needed by Vigil to decrypt the file, including information corresponding to:

- format version
- algorithm identifier
- random salt
- ML-KEM public key
- ML-KEM ciphertext
- encrypted ML-KEM private key
- AES-GCM nonce(s)
- encrypted file data

The design is intended to keep the cryptographic responsibilities separated and authenticated.

---

# 🖥️ User Interface

Vigil uses a dark, security-oriented PyQt6 interface.

### Main navigation

```text
┌──────────────────────────────────────────────────────┐
│  V I G I L                                  ⚙        │
├────────────────┬─────────────────────────────────────┤
│                │                                     │
│ 🛡️ AI IDS      │        Security Dashboard          │
│                │                                     │
│ 🔐 File Vault  │        Threat / Vault controls     │
│                │                                     │
│                │                                     │
└────────────────┴─────────────────────────────────────┘
```

The interface includes:

- 🛡️ AI Intrusion Detection
- 🔐 Secure File Vault
- ⚙️ Settings & Credentials
- 🌑 Dark security-focused theme
- 🚨 Threat notifications
- 🔒 Password-protected startup
- ⚠️ Protected factory reset

---

# 🚀 Getting Started

## Option A — Run from source

### 1. Clone the repository

```bash
git clone <YOUR-REPOSITORY-URL>
cd Vigil
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

or:

```cmd
.venv\Scripts\activate
```

### 3. Install dependencies

The current implementation uses these Python packages:

```bash
pip install PyQt6 cryptography pqcrypto scapy psutil numpy scikit-learn
```

> If the repository contains a `requirements.txt`, prefer installing from that file:
>
> ```bash
> pip install -r requirements.txt
> ```

### 4. Launch Vigil

```bash
python main.py
```

---

# 🔑 First Launch

On first launch, Vigil asks you to create a security profile.

You provide:

1. 🔐 Master password
2. 🔐 Password confirmation
3. ❓ Security question
4. 🔑 Recovery answer
5. 🔑 Recovery answer confirmation

### Password requirement

The current application requires:

> **Minimum: 12 characters**

Use a strong, unique password.

---

# 🔓 Login & Recovery

Normally:

```text
Launch Vigil
     │
     ▼
Master Password
     │
 ┌───┴────┐
 │        │
Valid    Invalid
 │        │
 ▼        ▼
Unlock   Attempts
           │
           ▼
      Recovery mode
```

After repeated password failures, the current UI offers the configured security question as a recovery credential.

⚠️ **Security note:** security-question recovery is inherently weaker than a strong random password because answers can sometimes be guessed or discovered. It should be treated as a convenience recovery mechanism, not equivalent to modern MFA.

---

# ⚙️ Settings

Vigil currently provides:

| Setting | Function |
|---|---|
| 🔑 Change Master Password | Requires the current password |
| ❓ Change Recovery Credentials | Updates the security question and answer |
| 🧨 Factory Reset | Removes local authentication configuration after password verification |

Factory reset is intentionally protected by the current master password.

---

# 📂 Using the File Vault

### Encrypt a file

1. Open **🔐 Secure File Vault**
2. Select a file
3. Enter the file encryption password
4. Start encryption
5. Vigil creates a `.vigil` archive

### Decrypt a file

1. Select the `.vigil` archive
2. Enter the corresponding encryption password
3. Vigil authenticates and decrypts the archive
4. The decrypted file is written to a temporary location and opened using the operating system's default application

### ⚠️ Temporary plaintext

For usability, the current implementation temporarily writes decrypted content to the operating system's temporary directory before opening it.

Therefore:

> The vault should **not** be described as guaranteeing that plaintext never touches disk.

If the file is highly sensitive, users should understand this limitation.

---

# 🧪 Technology Stack

| Layer | Technology |
|---|---|
| Language | 🐍 Python |
| Desktop UI | Qt / PyQt6 |
| Network capture / inspection | Scapy |
| Optional system networking data | psutil |
| Optional ML anomaly detection | NumPy + scikit-learn |
| Password KDF | scrypt |
| Post-quantum KEM | ML-KEM-768 |
| Key derivation | HKDF-SHA3-256 |
| File encryption | AES-256-GCM |
| Windows firewall response | Windows `netsh advfirewall` |
| Local configuration | JSON + Windows Registry marker |

---

# 🗂️ Project Structure

A typical repository layout is:

```text
Vigil/
│
├── core/
│   ├── auth_manager.py
│   ├── ai_ids_engine.py
│   └── pq_crypto.py
│
├── ui/
│   ├── auth_dialog.py
│   ├── ids_view.py
│   ├── vault_view.py
│   ├── settings_dialog.py
│   └── styles.py
│
├── main.py
│
├── README.md
├── SECURITY.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

---

# 🔐 Security & Privacy

Vigil is designed as a **local desktop application**.

The current source does not implement a cloud backend for:

- passwords
- vault keys
- encrypted files
- IDS events

Authentication configuration is stored locally under the user's Windows application-data area, in an instance-specific directory.

### What Vigil does **not** guarantee

Vigil is not a formally audited security product.

In particular:

- the application has not undergone a professional security audit
- the `pqcrypto` package's underlying implementations should not be treated as independently audited merely because the algorithms are standardized
- IDS detections can produce false positives or false negatives
- high entropy does not prove malicious activity
- ML anomaly detection is not a malware classifier
- decrypted vault files temporarily exist as plaintext on disk
- Windows Firewall actions can depend on operating-system permissions

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and security limitations.

---

# 🧪 Recommended Testing

Before relying on Vigil for important data, test:

- [ ] First-run initialization
- [ ] Correct password login
- [ ] Incorrect password handling
- [ ] Recovery flow
- [ ] Password change
- [ ] Factory reset
- [ ] Independent initialization of separate Vigil copies
- [ ] File encryption
- [ ] File decryption
- [ ] Wrong vault password rejection
- [ ] Corrupted `.vigil` archive rejection
- [ ] IDS startup/shutdown
- [ ] Port-scan detection
- [ ] SYN-burst detection
- [ ] Firewall block action
- [ ] Running without optional ML dependencies
- [ ] Running on a clean Windows installation

---

# ⚠️ Limitations

Vigil intentionally makes conservative claims.

### IDS

Network anomaly detection is probabilistic.

A detection means:

> **"This traffic matches a suspicious pattern."**

It does **not** automatically mean:

> **"This device is definitely compromised."**

### File Vault

The vault provides authenticated encryption and uses ML-KEM-768 in a hybrid design, but no software implementation should be considered invulnerable.

### Recovery

Security-question recovery is convenient but weaker than a strong password or modern multi-factor recovery mechanism.

### Windows Firewall

Firewall response changes the local Windows Firewall configuration and may require elevated privileges.

### Temporary Decryption

Decrypted files can temporarily exist on disk.

---

# 🧑‍💻 Development Philosophy

Vigil is built around several principles:

### 🔐 Security by separation

Different security problems use different primitives.

### 🧠 Detection by corroboration

Multiple signals are preferable to a single simplistic rule.

### 🛑 Conservative security claims

A security warning should not be presented as absolute proof without sufficient evidence.

### 👤 Human control

The user remains in control of firewall blocking, credentials, file encryption, and factory reset.

### 🧩 Practical engineering

The project focuses on understandable, demonstrable cybersecurity mechanisms rather than pretending to be a complete enterprise security platform.

---

# 🤝 Contributing

Contributions are welcome.

Useful contribution areas include:

- IDS detection improvements
- false-positive reduction
- additional tests
- Windows compatibility
- UI/UX improvements
- cryptographic review
- documentation
- performance improvements

Before submitting security-sensitive changes, read [`SECURITY.md`](SECURITY.md).

---

# 🐛 Bug Reports

For normal bugs, please open a GitHub Issue and include:

- Windows version
- Python version
- Vigil version/commit
- steps to reproduce
- expected behavior
- actual behavior
- relevant error message or traceback

**Do not publish passwords, private keys, `.vigil` files containing sensitive information, or other secrets in an issue.**

---

# 📜 License

This project is distributed under the license contained in [`LICENSE`](LICENSE).

If no license has yet been added to the repository, add one before treating the project as an open-source release.

---

# ⚖️ Responsible Use

Vigil is intended for:

- your own computer
- systems you are authorized to monitor
- educational cybersecurity research
- defensive security experimentation
- authorized lab environments

Do not use network monitoring or firewall functionality against systems or networks without authorization.

---

# 🌟 Project Highlights

```text
          ┌─────────────────────────────┐
          │          🛡️ VIGIL           │
          │     AI SECURITY SUITE       │
          └──────────────┬──────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
     🛡️ NETWORK                    🔐 DATA
     SECURITY                      SECURITY
          │                             │
   ┌──────┼──────┐              ┌──────┼──────┐
   │      │      │              │      │      │
  Scan   SYN   Entropy        ML-KEM  HKDF   AES-GCM
   │      │      │              │      │      │
   └──────┴──────┘              └──────┴──────┘
          │                             │
          └──────────────┬──────────────┘
                         │
                    👤 USER CONTROL
```

---

<div align="center">

### 🛡️ **Vigil — Watch the Network. Protect the Data.**

Built as a practical cybersecurity showcase combining **network defense**, **modern cryptography**, and **desktop security engineering**.

</div>
