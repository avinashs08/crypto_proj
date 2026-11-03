# System Architecture & Cryptographic Specifications

## 1. Weak Authentication Attack Flow

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Victim (Alice)
    actor Eve as Attacker (Eve / Wireshark)
    participant Server as Insecure Server

    Note over Alice,Server: Insecure HTTP Basic Auth (Port 80)
    Alice->>Server: POST /auth/basic (Authorization: Basic YWxpY2U6cGFzc3dvcmQxMjM=)
    Eve-->>Alice: [Promiscuous Sniff] Captures raw packet & decodes credentials
    Server->>Alice: 200 OK + Static Token: 482c811da5...

    Note over Eve,Server: ATTACK 1: Credential Extraction
    Note over Eve: Eve decodes Base64 -> alice:password123

    Note over Eve,Server: ATTACK 2: Token Replay Attack
    Eve->>Server: POST /transfer_funds (Authorization: Bearer 482c811da5...)
    Note over Server: Server lacks nonce/timestamp check!
    Server-->>Eve: 200 OK (Transfer 50,000 USD executed for Alice!)
```

---

## 2. Kerberos v5 (RFC 4120) Protocol Architecture

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client (Alice)
    participant AS as KDC: Authentication Server
    participant TGS as KDC: Ticket Granting Server
    participant Server as Application Server (Fileserver)
    actor Attacker as Attacker (Eve Replay)

    Note over Client,AS: 1. AS Exchange (Initial Authentication)
    Client->>AS: AS-REQ: Client ID, Service=krbtgt, Nonce_1
    AS->>Client: AS-REP: E_Kc[Kc,tgs, Nonce_1, TGT=E_Ktgs[Client, Kc,tgs, Expiry]]
    Note over Client: Alice decrypts AS-REP using Kc = PBKDF2(Password)

    Note over Client,TGS: 2. TGS Exchange (Service Ticket Issuance)
    Client->>TGS: TGS-REQ: [TGT, Authenticator=E_Kc,tgs[Client, Timestamp_1], Service=fileserver]
    Note over TGS: TGS decrypts TGT with Ktgs, decrypts Authenticator with Kc,tgs, verifies timestamp
    TGS->>Client: TGS-REP: E_Kc,tgs[Kc,s, ServiceTicket=E_Kv[Client, Kc,s, Expiry]]

    Note over Client,Server: 3. AP Exchange (Mutual Authentication)
    Client->>Server: AP-REQ: [ServiceTicket, Authenticator=E_Kc,s[Client, Timestamp_2]]
    Note over Server: Server decrypts ServiceTicket with Kv, decrypts Authenticator with Kc,s
    Note over Server: Server logs (Client, Timestamp_2) in Replay Cache
    Server->>Client: AP-REP: E_Kc,s[Timestamp_2 + 1] (Mutual Authentication Proven)

    Note over Attacker,Server: 4. Attacker Replay Attempt
    Attacker->>Server: Replays Sniffed AP-REQ with Timestamp_2
    Note over Server: Replay Cache detects duplicate (Client, Timestamp_2)!
    Server-->>Attacker: KRB_AP_ERR_REPEAT: Request Rejected!
```

---

## 3. Public Key Infrastructure (PKI) & Mutual TLS (mTLS) Architecture

```mermaid
sequenceDiagram
    autonumber
    actor CA as Root Certificate Authority (CA)
    participant Client as Client (Alice)
    participant Server as Application Server

    Note over CA: Root CA signs own Certificate with RSA-2048
    CA->>Client: Trust Store configured with Root CA Public Key
    CA->>Server: Trust Store configured with Root CA Public Key
    CA->>Client: Issues X.509 Client Certificate (signed by Root CA)
    CA->>Server: Issues X.509 Server Certificate (signed by Root CA)

    Note over Client,Server: Mutual TLS 1.3 Handshake (Zero-Trust)
    Client->>Server: 1. ClientHello (ClientRandom, Supported Ciphers)
    Server->>Client: 2. ServerHello (ServerRandom, Selected Cipher) + Server Certificate + CertificateRequest
    Note over Client: 3. Client verifies Server Cert signature using Root CA Public Key
    Client->>Server: 4. Client Certificate + Encrypted PreMasterSecret (E_Kpub_server[PMS]) + CertificateVerify (Sign_Kpriv_client[Hash])
    Note over Server: 5. Server verifies Client Cert with Root CA, verifies CertificateVerify with Client Public Key
    Note over Client,Server: 6. Both derive Master Secret & AES-256 Symmetric Session Key via HMAC-SHA256
    Client->>Server: 7. Finished (Encrypted with Session Key)
    Server->>Client: 8. Finished (Encrypted with Session Key)
    Note over Client,Server: 9. Secure Application Tunnel Active (AES-256-GCM)
```

