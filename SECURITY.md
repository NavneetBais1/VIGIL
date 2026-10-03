# 🔐 Security Policy — Vigil

Thank you for helping improve the security of **Vigil**.

Vigil is a security-focused Windows desktop project containing network-monitoring, firewall-response, authentication, and post-quantum file-encryption functionality.

Because security issues can expose users to real risk, please report vulnerabilities responsibly.

---

## 🚨 Reporting a Vulnerability

### Preferred method — private GitHub security reporting

If this repository has **GitHub Private Vulnerability Reporting** or **GitHub Security Advisories** enabled, please use the repository's **Security** section to submit the vulnerability privately.

This is preferred over creating a public issue because it gives the maintainer an opportunity to investigate and fix the problem before public disclosure.

> **Do not open a public GitHub Issue for an undisclosed security vulnerability.**

### If private reporting is not enabled

Contact the repository maintainer through the contact method published in the repository profile/about section.

When contacting the maintainer, include:

- A clear description of the vulnerability
- The affected component/file
- The affected version or commit
- Reproduction steps
- A minimal proof of concept, where appropriate
- Security impact
- Any relevant logs or screenshots
- A suggested mitigation, if you have one

Please avoid sending passwords, private keys, personal information, or sensitive files.

---

# 🧭 What Should Be Reported?

Security issues include, but are not limited to:

### 🔑 Authentication

- Authentication bypasses
- Credential verification flaws
- Recovery-flow bypasses
- Incorrect authorization
- Credential leakage
- Authentication state corruption

### 🔐 Cryptography / Vault

- Incorrect cryptographic construction
- Authentication-tag bypass
- Key reuse
- Nonce reuse
- Weak key derivation
- Archive parsing vulnerabilities
- Decryption bypasses
- Plaintext leakage beyond documented behavior

### 🛡️ IDS / Firewall

- Unauthorized firewall-rule creation
- Command injection
- Unsafe handling of attacker-controlled IP addresses
- Privilege-escalation paths
- Network data causing code execution
- Remote code execution

### 💻 Application Security

- Arbitrary code execution
- Path traversal
- Unsafe file handling
- Unsafe subprocess invocation
- Sensitive information disclosure
- Local privilege escalation
- Dependency vulnerabilities with a meaningful impact on Vigil

---

# 🟡 Issues That May Not Be Security Vulnerabilities

The following are generally normal bugs unless they create a security impact:

- UI layout problems
- Cosmetic issues
- False-positive IDS alerts
- False-negative IDS alerts without an additional exploit
- Performance problems
- Unsupported Windows configurations
- Feature requests
- Documentation mistakes

For these, please use normal GitHub Issues instead.

---

# 🔒 Current Security Design

## Application Authentication

The current authentication implementation:

- Uses **scrypt** for password-derived credentials.
- Uses separate random salts for the master password and recovery answer.
- Requires a minimum master-password length of **12 characters**.
- Stores authentication state outside the source/project directory.
- Uses a per-instance data namespace.
- Uses a Windows Registry initialization marker.
- Uses atomic configuration writes.
- Contains compatibility handling for older Vigil credential formats.

---

# 🔐 File Vault

The current vault uses a hybrid construction based on:

| Primitive | Purpose |
|---|---|
| **ML-KEM-768** | Post-quantum key encapsulation |
| **HKDF-SHA3-256** | Derivation of the AES data key |
| **AES-256-GCM** | Authenticated file encryption |
| **scrypt** | Password-based wrapping of the ML-KEM private key |

Each vault archive generates fresh ML-KEM key material.

The current archive format is identified by:

```text
VIGIL_PQ_V3
```

---

# 🛡️ IDS Security Model

The IDS combines several detection signals:

```text
             Network Traffic
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     Port Scan    SYN Burst   Entropy
        │           │           │
        └───────────┼───────────┘
                    ▼
             Corroborating
                signals
                    │
                    ▼
             Threat Event
                    │
                    ▼
          Optional user action
                    │
                    ▼
            Windows Firewall
```

The IDS intentionally does **not** treat every anomaly as proof of compromise.

For example:

- High entropy can be legitimate encryption or compression.
- An unusual packet can be legitimate application traffic.
- A network scan can occur in an authorized environment.

The IDS should therefore be treated as a **detection and investigation aid**, not an infallible security oracle.

---

# ⚠️ Important Security Limitations

## 1. Recovery-question authentication

The current application allows recovery through the configured security question after repeated password failures.

This is weaker than a strong random password or a modern multi-factor recovery mechanism.

Users should therefore choose a recovery answer that is not publicly discoverable.

The recovery answer should **not** be reused as a password on another service.

---

## 2. Temporary plaintext during vault decryption

The current vault decrypts the file and writes the resulting plaintext to a temporary operating-system location before opening it with the default application.

Therefore:

> Vigil does not currently guarantee that decrypted plaintext never touches disk.

Applications that open the plaintext may also create their own temporary files, caches, backups, or recent-file records.

Users handling highly sensitive data should account for this limitation.

---

## 3. IDS accuracy

Vigil's IDS is heuristic.

It can produce:

- false positives
- false negatives
- incomplete visibility
- incorrect classification of unusual but legitimate traffic

Detection thresholds are designed for a practical desktop demonstration rather than a formally validated enterprise detection model.

---

## 4. Machine-learning detection

The optional ML layer is not a trained malware classifier.

It uses an anomaly-detection model and treats the result as a secondary signal.

An ML anomaly should therefore be interpreted as:

> "This traffic looks unusual compared with the learned baseline."

It should not be interpreted as:

> "This packet is malicious."

---

## 5. Windows Firewall changes

Vigil can create Windows Firewall rules as part of its response functionality.

Firewall modifications affect the local operating system and can interfere with connectivity if used incorrectly.

The application may require appropriate Windows permissions for this operation.

---

## 6. Cryptographic implementation audit status

The use of standardized cryptographic algorithms does not by itself mean that the complete Vigil implementation has been formally audited.

The application and its cryptographic integration should therefore be considered **unaudited software**.

The underlying `pqcrypto` package documentation also states that its underlying implementations have not undergone a formal security audit.

Do not describe Vigil as "formally audited", "certified", or "military-grade" unless an appropriate independent audit or certification has actually been completed.

---

# 🧪 Security Testing

Before each public release, maintainers should test at minimum:

### Authentication

- [ ] First-run initialization
- [ ] Correct-password authentication
- [ ] Incorrect-password handling
- [ ] Recovery attempt limits
- [ ] Password change
- [ ] Recovery credential change
- [ ] Factory reset authorization
- [ ] Deleted/corrupted configuration behavior
- [ ] Separate-instance authentication isolation

### Vault

- [ ] Encrypt/decrypt round trip
- [ ] Wrong password rejection
- [ ] Modified ciphertext rejection
- [ ] Modified metadata rejection
- [ ] Truncated archive rejection
- [ ] Malformed archive rejection
- [ ] Large-file behavior
- [ ] `.vigil` archive handling
- [ ] Temporary-file cleanup behavior

### IDS

- [ ] Port-scan detection
- [ ] SYN-burst detection
- [ ] Entropy detection
- [ ] ML-disabled operation
- [ ] ML-enabled operation
- [ ] Alert cooldown behavior
- [ ] Firewall block action
- [ ] Invalid IP handling
- [ ] Local/loopback traffic handling

### Application

- [ ] No hard-coded secrets
- [ ] No `shell=True` in security-sensitive subprocess calls
- [ ] No unsafe path construction
- [ ] Dependency review
- [ ] Static analysis
- [ ] Clean-install test on Windows
- [ ] GitHub secret scanning

---

# 🔍 Secure Development Checklist

Before pushing a release:

```text
[ ] No passwords committed
[ ] No API keys committed
[ ] No private keys committed
[ ] No personal Windows paths committed
[ ] No test vaults containing real data
[ ] No .env files committed
[ ] No generated credentials committed
[ ] No build artifacts committed
[ ] No __pycache__ directories committed
[ ] Dependencies reviewed
[ ] Security-sensitive subprocess calls reviewed
[ ] Vault round-trip tested
[ ] Authentication tested
[ ] GitHub secret scanning enabled
[ ] Dependabot enabled where appropriate
[ ] Code scanning enabled where appropriate
```

GitHub recommends repository security features such as **Dependabot alerts, secret scanning, push protection, and code scanning** for public repositories. These complement, but do not replace, secure application design and testing.

---

# 📦 Supported Versions

Until a formal release/versioning policy is established:

| Version | Security support |
|---|---|
| Current repository version | ✅ Supported |
| Older development snapshots | ⚠️ Best effort |
| Unmodified forks | ❌ Not maintained by this project |

For vulnerability reports, always include the exact commit or release you tested.

---

# 🧑‍🔬 Responsible Disclosure

A responsible disclosure process should generally follow:

```text
Researcher
    │
    │ private report
    ▼
Maintainer
    │
    ├── Reproduce
    │
    ├── Assess severity
    │
    ├── Develop fix
    │
    ├── Test fix
    │
    └── Release update
    │
    ▼
Public disclosure
```

Please avoid public disclosure of a vulnerability before the maintainer has had a reasonable opportunity to investigate and address it.

---

# 📝 What a Good Report Looks Like

Example:

```text
Title:
Authentication bypass through recovery flow

Affected component:
core/auth_manager.py
ui/auth_dialog.py

Affected version:
<version or commit>

Impact:
An attacker who knows/discovers the recovery answer may obtain
application access without the master password.

Steps to reproduce:
1. ...
2. ...
3. ...

Expected behavior:
...

Actual behavior:
...

Proof of concept:
...

Suggested mitigation:
...
```

Keep proof-of-concept material to the minimum necessary to demonstrate the issue.

---

# 🚫 Do Not Include

Please do **not** submit:

- Real passwords
- Recovery answers
- Private keys
- Real `.vigil` files containing sensitive data
- Personal documents
- API credentials
- Tokens
- Cookies
- Windows account credentials
- Other people's personal information

Sanitize logs and screenshots before submission.

---

# 🏫 Project Context

Vigil is primarily an educational and showcase-oriented cybersecurity project.

Its purpose is to demonstrate practical implementation of:

- defensive network monitoring
- anomaly detection
- Windows security controls
- password protection
- post-quantum cryptographic concepts
- authenticated encryption
- secure desktop application design

It is **not** presented as a substitute for enterprise EDR, SIEM, DLP, antivirus, incident-response tooling, or professionally audited cryptographic software.

---

# 📬 Contact

For security reports, use the repository's private security-reporting mechanism when available.

For ordinary bugs and feature requests, use GitHub Issues.

If you maintain a dedicated security email, replace this section with:

```text
Security contact:
security@example.com

PGP key:
<optional public-key fingerprint / link>
```

Do not publish a private key.

---

<div align="center">

### 🔐 Security is a process, not a checkbox.

**Thank you for helping make Vigil safer.**

</div>
