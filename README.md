# Cryptography and Network Security (CNS) Suite
### Real-Life Engineering Project: Weak Authentication Attack Simulation vs. Strong Authentication (Kerberos & PKI/mTLS)

![CNS Lab Banner](public/css/style.css)

---

## 📌 Project Overview
This project delivers a **fully functional, real-world, interactive cybersecurity engineering platform** that demonstrates the vulnerabilities of weak authentication schemes and contrasts them against enterprise-grade strong authentication protocols: **Kerberos v5 (RFC 4120)** and **Public Key Infrastructure (PKI) with Mutual TLS (mTLS)**.

Built entirely using native Node.js standard cryptographic subsystems (`node:crypto`), this project requires **zero external dependencies** and runs out-of-the-box on any system.

### 🎓 Academic & Curriculum Outcome Alignment
- **PO3 (Design/Development of Solutions)**: Complete multi-tiered cryptographic protocol design resolving credential interception and token replay.
- **PO5 (Modern Tool Usage)**: Modern cryptographic engines (RSA-2048, AES-256-GCM, PBKDF2, SHA-256 HMAC) with real-time packet inspection.
- **PO7 (Environment & Sustainability)**: Computational overhead and CPU energy efficiency benchmarking (Symmetric vs Asymmetric).
- **PO8 (Ethics)**: Ethical offensive simulation in a controlled educational sandbox for defensive engineering.
- **PSO2 (Program Specific Outcome - CNS)**: Practical mastery of Kerberos ticket flows, X.509 certificates, and Zero-Trust mTLS.
- **SDG 4 (Quality Education)**: Interactive pedagogical lab environment demystifying abstract security formulas.
- **SDG 9 (Industry, Innovation & Infrastructure)**: Hardening enterprise IT and critical infrastructure against cyber attacks.

---

## 🚀 Quickstart & How to Run

### Step 1: Run the Automated Test Suite (26/26 Tests)
Verify all cryptographic primitives, attack simulations, and defense mechanisms:
```bash
node test_all.js
```
Expected output:
```text
====================================================
CNS SECURITY SUITE: AUTOMATED MODULE TEST VERIFICATION
====================================================
...
TOTAL TESTS: 26 | PASSED: 26 | FAILED: 0
====================================================
```

### Step 2: Start the Cyber Security Operations Center (SOC) Server
```bash
node server.js
```
or
```bash
npm start
```

### Step 3: Open the Interactive Web Dashboard
Navigate to:
```text
http://localhost:3000
```

---

## 🔬 Lab Modules Walkthrough

### Module 1: Weak Authentication Attack Lab
1. **Plaintext Sniffing**: Alice logs in via HTTP Basic Auth. The adversary tap intercepts cleartext credentials from the network wire (CWE-319).
2. **Token Replay Attack**: Alice authenticates and receives a weak static token. Eve intercepts the token and re-transmits it to execute unauthorized transactions (CWE-294).
3. **Dictionary & Rainbow Table Cracking**: Demonstrates sub-millisecond cracking of unsalted MD5 hashes (`482c811da5d5b4bc...` cracked to `password123` in $0.21 \text{ ms}$). Shows why Salted PBKDF2 is required.

### Module 2: Kerberos v5 Strong Authentication Lab
1. **AS Exchange**: Client requests Ticket Granting Ticket (TGT) from Authentication Server (AS). Client decrypts response with password-derived key $K_C$.
2. **TGS Exchange**: Client presents encrypted TGT and Authenticator to Ticket Granting Server (TGS) to receive a Service Ticket (ST) encrypted with Service Key $K_V$.
3. **AP Exchange & Mutual Authentication**: Client presents ST and Service Authenticator to Application Server. Server responds with $(\text{Timestamp} + 1)$, proving mutual identity.
4. **Attacker Replay Defense Test**: Attacker Eve sniffs Alice's `AP-REQ` and attempts to replay it. The server's **Replay Cache** flags the duplicate timestamp and drops the connection with `KRB_AP_ERR_REPEAT`!

### Module 3: PKI & Zero-Trust Mutual TLS (mTLS) Lab
1. **Certificate Authority (Root CA)**: Self-signs a Root CA certificate using 2048-bit RSA keys.
2. **X.509 Certificate Issuance**: Generates CSRs with Proof of Possession and issues signed digital certificates.
3. **mTLS Handshake**: Executes a complete 6-step Mutual TLS handshake:
   - Server authenticates to Client via Root CA signature check.
   - Client authenticates to Server via Client Certificate and `CertificateVerify` RSA digital signature.
   - Master Secret and symmetric AES-256 session key derived via PRF/HMAC-SHA256.
4. **Certificate Revocation (CRL Test)**: Revoking a certificate immediately breaks the handshake with `CERTIFICATE_REVOKED`.

### Module 4: Comparative Benchmark Matrix
Detailed side-by-side comparison across 10 security parameters:
- Cryptographic primitive
- Replay attack resistance
- Sniffing immunity
- Mutual authentication
- Single point of failure
- Computational overhead

### Module 5: Program Outcomes & Viva Voce Guide
- Full explanations of PO3, PO5, PO7, PO8, PSO2 and SDG 4, SDG 9.
- Top 25 Viva Voce questions with detailed model answers.

---

## 📂 Project Directory Structure

```text
crypto_proj/
├── server.js               # Zero-dependency Node.js HTTP server & REST API
├── package.json            # Project manifest & npm scripts
├── test_all.js             # Automated 26-test suite verifying all crypto operations
├── src/
│   └── crypto/
│       ├── weakAuth.js     # Weak auth: plaintext, unsalted MD5, static tokens
│       ├── attacks.js      # Attack engine: packet sniffer, token replay, dictionary cracker
│       ├── kerberos.js     # Kerberos v5 KDC (AS/TGS), tickets, authenticators, replay cache
│       └── pki.js          # PKI engine: Root CA, CSRs, X.509 certs, mTLS handshake, CRL
├── public/
│   ├── index.html          # Modern Cyber Security Operations Center (SOC) dashboard
│   ├── css/
│   │   └── style.css       # High-tech dark glassmorphism styling
│   └── js/
│       └── app.js          # Real-time interactive UI logic & REST API bindings
└── docs/
    ├── PROJECT_REPORT.md   # Formal academic project report
    ├── ARCHITECTURE.md     # Protocol flowcharts & Mermaid sequence diagrams
    └── VIVA_QUESTIONS.md   # 25 Viva Voce defense questions and answers
```

---

## 🛡️ License & Academic Usage
This project is developed for educational and academic laboratory evaluation in Cryptography & Network Security.
Licensed under the **MIT License**.

