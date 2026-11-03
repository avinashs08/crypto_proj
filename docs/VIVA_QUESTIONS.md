# Comprehensive Viva Voce Questions & Answers (CNS Lab Project)

## Section 1: Weak Authentication & Attacks

### Q1: What constitutes "weak authentication"?
**Answer:** Weak authentication refers to mechanisms that fail to ensure confidentiality, integrity, or replay immunity of user identity verification. Examples include:
1. Cleartext / Base64 password transmission (HTTP Basic Auth, FTP, Telnet).
2. Unsalted or cryptographically broken hashes (MD5, SHA-1).
3. Static, non-expiring session tokens lacking embedded nonces or cryptographic signatures.
4. One-way authentication where the client does not verify server authenticity.

### Q2: Why is Base64 encoding in HTTP Basic Auth not considered encryption?
**Answer:** Base64 is merely a binary-to-text representation scheme designed to safely transmit 8-bit binary data over 7-bit ASCII transmission channels. It uses a known, fixed reversible substitution table and possesses zero mathematical keys. Anyone intercepting a Base64 string can decode it instantly without any key.

### Q3: What is a Replay Attack and why does it succeed against weak systems?
**Answer:** A replay attack occurs when an attacker eavesdrops on a network, intercepts a valid authentication credential or token, and later re-transmits it to the server to fraudulently gain access. It succeeds against weak systems because the server only validates whether the token exists in its database, failing to verify:
1. Message freshness (timestamps).
2. One-time nonces.
3. Cryptographic binding to the original client session.

### Q4: Why are unsalted MD5 hashes vulnerable to dictionary and rainbow table attacks?
**Answer:** MD5 is deterministic: the same input string always produces the exact same 128-bit hash. Attackers precompute lookup tables ("rainbow tables") mapping billions of common passwords to their MD5 hashes. When an attacker acquires a database of unsalted hashes, looking up the plaintext password takes microseconds. Adding a cryptographic salt (random bytes per user) guarantees that even if two users choose identical passwords, their resulting hashes are unique, completely invalidating precomputed rainbow tables.

---

## Section 2: Kerberos v5 (RFC 4120)

### Q5: What is the Key Distribution Center (KDC) in Kerberos?
**Answer:** The KDC is a trusted third-party authentication server composed of two logical entities:
1. **Authentication Server (AS)**: Verifies the initial identity of the user and issues the Ticket Granting Ticket (TGT).
2. **Ticket Granting Service (TGS)**: Verifies the TGT and issues Service Tickets (ST) for specific application servers.

### Q6: Why is the client's password never sent across the network in Kerberos?
**Answer:** During the AS exchange, the client only sends its username/principal and a request for a TGT. The AS looks up the user's secret key $K_C$ (derived from the user's password) in the KDC database, encrypts the reply with $K_C$, and transmits it back. Only someone who knows the correct password can derive $K_C$ and decrypt the response. Thus, the password never traverses the wire.

### Q7: What is inside a Ticket Granting Ticket (TGT)?
**Answer:** A TGT contains:
- Client Principal ID ($C$).
- Client-TGS Session Key ($K_{C, TGS}$).
- Timestamp of issuance.
- Ticket lifetime and expiration.
- Client network address / realm.
The entire TGT is encrypted using the TGS's secret key ($K_{TGS}$). Because the client does not possess $K_{TGS}$, the client cannot inspect or tamper with the TGT.

### Q8: What is an Authenticator in Kerberos, and why is it needed if the client already has a ticket?
**Answer:** A ticket is reusable throughout its validity window (e.g., 8 hours). If an attacker intercepts the ticket on the network wire, the attacker might try to use it. The **Authenticator** solves this: it contains the client's identity and the current timestamp, encrypted with the short-lived session key ($K_{C, TGS}$ or $K_{C, S}$). The server decrypts the Authenticator and checks if the timestamp is fresh (within $\pm 5$ minutes). An attacker who intercepts a ticket cannot generate a valid fresh Authenticator without knowing the session key.

### Q9: How does Kerberos prevent Replay Attacks?
**Answer:** Kerberos employs two complementary defenses:
1. **Clock Skew Tolerance**: The server rejects authenticators whose timestamps deviate from server time by more than a predefined window (typically 5 minutes).
2. **Server Replay Cache**: The application server logs every `(ClientPrincipal, Timestamp)` tuple received within the 5-minute window. If an attacker replays the exact captured `AP-REQ` within that window, the server finds the entry in its replay cache and immediately aborts the connection with error `KRB_AP_ERR_REPEAT`.

### Q10: How does Kerberos achieve Mutual Authentication?
**Answer:** In the AP exchange, the client sends `AP-REQ` requesting mutual authentication. The server decrypts the ticket and authenticator, increments the client's timestamp by 1, encrypts this value with the shared service session key ($K_{C, S}$), and sends it back in `AP-REP`. Because only the genuine application server possesses $K_V$ to extract $K_{C, S}$, receiving $(\text{timestamp} + 1)$ mathematically proves to the client that the server is genuine and not a rogue phishing server.

---

## Section 3: Public Key Infrastructure (PKI) & Mutual TLS (mTLS)

### Q11: What is Public Key Infrastructure (PKI)?
**Answer:** PKI is a comprehensive framework consisting of hardware, software, policies, and standards that manages digital certificates and public-key cryptography. It establishes trust in digital identities across open networks without requiring pre-shared secret keys.

### Q12: What are the main components of an X.509 Digital Certificate?
**Answer:**
1. Version Number (v3).
2. Serial Number (unique identifier assigned by the CA).
3. Signature Algorithm (e.g., `sha256WithRSAEncryption`).
4. Issuer Name (Distinguished Name of the issuing CA).
5. Validity Period (`notBefore` and `notAfter` UTC dates).
6. Subject Name (Distinguished Name of the entity being certified).
7. Subject Public Key Info (Algorithm and raw public key bytes).
8. Extensions (Key Usage, Subject Alternative Name).
9. CA Digital Signature.

### Q13: What is a Certificate Signing Request (CSR)?
**Answer:** A CSR is an encoded message sent by an applicant to a Certificate Authority. It contains the applicant's Distinguished Name, public key, and a digital signature created using the applicant's private key. This signature provides **Proof of Possession (PoP)**, verifying that the applicant actually owns the private key corresponding to the public key in the request.

### Q14: How does a client verify an X.509 Certificate?
**Answer:**
1. **Chain of Trust**: Checks that the certificate was signed by a trusted Root or Intermediate CA in the client's local trust store.
2. **Mathematical Signature Verification**: Decrypts the certificate's digital signature using the CA's public key and verifies that it matches the SHA-256 hash of the certificate's body.
3. **Temporal Validity**: Ensures the current time is between `notBefore` and `notAfter`.
4. **Revocation Status**: Verifies the certificate serial number is not listed in the Certificate Revocation List (CRL) or via OCSP.
5. **Subject Identity**: Confirms the Common Name (CN) or SAN matches the server's domain.

### Q15: What is the difference between standard TLS and Mutual TLS (mTLS)?
**Answer:**
- In **Standard TLS (One-Way)**: Only the server presents an X.509 certificate to authenticate itself to the client. The client's identity remains anonymous or is authenticated at the application layer using a password/API token.
- In **Mutual TLS (Two-Way / mTLS)**: Both client and server present X.509 digital certificates. The server sends a `CertificateRequest`, and the client transmits its certificate along with a `CertificateVerify` message signed with the client's private key. Both endpoints cryptographically verify each other before exchanging application data, realizing a Zero-Trust security model.

---

## Section 4: Program Outcomes & SDG Justifications

### Q16: How does this project map to PO3 (Design/Development of Solutions)?
**Answer:** PO3 requires students to design complex engineering solutions that meet specified security needs. In this project, we designed protocol state machines for both symmetric (Kerberos AS/TGS/AP) and asymmetric (PKI/mTLS) authentication that resolve the fundamental vulnerabilities of network sniffing, replay attacks, and credential spoofing.

### Q17: How does this project map to PO5 (Modern Tool Usage)?
**Answer:** PO5 emphasizes modern engineering and IT tools. We utilized modern cryptographic libraries (`node:crypto`), automated software testing frameworks (26 integration tests), and browser-based real-time protocol visualization suites to model complex network interactions.

### Q18: How does this project map to PO7 (Environment and Sustainability)?
**Answer:** PO7 examines sustainability. In hyperscale enterprise environments, cryptographic CPU cycles directly translate to electrical power consumption and carbon footprint. Kerberos utilizes hardware-accelerated symmetric AES operations, consuming over 100x fewer CPU cycles than repeated RSA asymmetric modular exponentiations. Understanding these architectural trade-offs allows engineers to design energy-efficient security pipelines.

### Q19: How does this project map to PO8 (Ethics)?
**Answer:** PO8 focuses on professional ethics. Security researchers must understand offensive tactics to design resilient defenses. This project executes sniffing, replay, and hash-cracking attacks strictly inside an isolated local educational sandbox, emphasizing responsible disclosure and data privacy protection.

### Q20: How does this project support SDG 4 (Quality Education) and SDG 9 (Industry, Innovation & Infrastructure)?
**Answer:**
- **SDG 4**: Provides an open, hands-on pedagogical simulation tool that makes abstract mathematical cryptography interactive and intuitive for students.
- **SDG 9**: Secures foundational digital infrastructure (cloud services, industrial IoT, financial transactions) by providing hardened blueprints for modern enterprise authentication.

