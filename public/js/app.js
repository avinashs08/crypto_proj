// public/js/app.js - Cybersecurity Dashboard Operations and Interactive Simulator
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  fetchSystemStatus();
  attachWeakAuthEvents();
  attachKerberosEvents();
  attachPKIEvents();
  fetchComparisonMatrix();
});

// Tab Switcher
function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetId = tab.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });
}

// Fetch System Initial Status
async function fetchSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    console.log('CNS Suite Status:', data);
    document.getElementById('stat-ca').textContent = 'CA Online';
    document.getElementById('stat-kdc').textContent = 'KDC Online';
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

// Helper to log to interactive terminal
function printLog(elementId, text, type = 'info') {
  const terminal = document.getElementById(elementId);
  if (!terminal) return;
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = `terminal-${type}`;
  line.textContent = `[${time}] ${text}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// ==========================================
// 1. WEAK AUTHENTICATION & ATTACK SIMULATION
// ==========================================
let capturedWeakPacket = null;
let capturedWeakToken = null;

function attachWeakAuthEvents() {
  // Alice Login (Weak)
  document.getElementById('btn-weak-login').addEventListener('click', async () => {
    const username = document.getElementById('weak-username').value;
    const password = document.getElementById('weak-password').value;
    printLog('log-weak-client', `Initiating unencrypted HTTP Basic Auth for user '${username}'...`, 'info');

    try {
      const res = await fetch('/api/weak-auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (data.success) {
        capturedWeakPacket = data.packetTrace;
        capturedWeakToken = data.token;
        printLog('log-weak-client', `Login Successful! Server issued Weak Static Token: ${data.token}`, 'success');
        printLog('log-weak-client', `Wire data broadcast over plaintext port 80.`, 'warning');
        document.getElementById('wire-sniff-btn').disabled = false;
        document.getElementById('wire-replay-btn').disabled = false;
        document.getElementById('captured-token-display').textContent = data.token;
      } else {
        printLog('log-weak-client', `Login Failed: ${data.error}`, 'danger');
      }
    } catch (err) {
      printLog('log-weak-client', `Connection Error: ${err.message}`, 'danger');
    }
  });

  // ATTACK 1: Sniff Packet
  document.getElementById('wire-sniff-btn').addEventListener('click', async () => {
    printLog('log-weak-attacker', `[Eve/Wireshark] Promiscuous network tap active. Sniffing unencrypted packets on subnet...`, 'warning');

    try {
      const res = await fetch('/api/weak-auth/attack-sniff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet: capturedWeakPacket })
      });
      const data = await res.json();

      if (data.hijackSuccess) {
        printLog('log-weak-attacker', `ALERT: Cleartext credentials intercepted!`, 'danger');
        printLog('log-weak-attacker', `Decoded Username: ${data.extractedCredentials.username}`, 'danger');
        printLog('log-weak-attacker', `Decoded Password: ${data.extractedCredentials.password}`, 'danger');
        printLog('log-weak-attacker', `Vulnerability: ${data.vulnerability}`, 'purple');
        document.getElementById('crack-target-hash').value = '482c811da5d5b4bc6d497ffa98491e38';
      }
    } catch (err) {
      printLog('log-weak-attacker', `Sniffer Error: ${err.message}`, 'danger');
    }
  });

  // ATTACK 2: Replay Stolen Token
  document.getElementById('wire-replay-btn').addEventListener('click', async () => {
    printLog('log-weak-attacker', `[Eve] Initiating Replay Attack... Re-transmitting Alice's captured Bearer token to fraudulent fund transfer endpoint!`, 'warning');

    try {
      const res = await fetch('/api/weak-auth/attack-replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: capturedWeakToken, action: 'fraudulent_wire_transfer_50000_USD' })
      });
      const data = await res.json();

      if (data.serverAccepted) {
        printLog('log-weak-attacker', `EXPLOIT SUCCESSFUL! Vulnerable server accepted replayed token without nonce or timestamp freshness check!`, 'danger');
        printLog('log-weak-attacker', `Action Executed: ${data.targetAction} on behalf of victim '${data.victimUser}'`, 'danger');
        printLog('log-weak-attacker', `Impact: ${data.impact}`, 'purple');
      } else {
        printLog('log-weak-attacker', `Replay failed: ${data.error}`, 'info');
      }
    } catch (err) {
      printLog('log-weak-attacker', `Replay Error: ${err.message}`, 'danger');
    }
  });

  // ATTACK 3: Dictionary Hash Crack
  document.getElementById('btn-crack-hash').addEventListener('click', async () => {
    const hash = document.getElementById('crack-target-hash').value;
    printLog('log-weak-attacker', `Launching GPU-accelerated Rainbow Table / Dictionary Attack against MD5 hash: ${hash}`, 'warning');

    try {
      const res = await fetch('/api/weak-auth/attack-crack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash, algorithm: 'md5' })
      });
      const data = await res.json();

      if (data.cracked) {
        printLog('log-weak-attacker', `CRACKED IN ${data.timeTakenMicroseconds} microseconds!`, 'danger');
        printLog('log-weak-attacker', `Recovered Plaintext Password: "${data.crackedPassword}"`, 'danger');
        printLog('log-weak-attacker', `CWE-327: Broken Cryptography. Unsalted MD5 has 0 preimage protection.`, 'purple');
        printLog('log-weak-attacker', `Mitigation: Use Salted PBKDF2 (Sample: ${data.mitigationDemonstration.samplePBKDF2Hash.substring(0, 24)}...)`, 'success');
      } else {
        printLog('log-weak-attacker', `Hash not found in current wordlist.`, 'info');
      }
    } catch (err) {
      printLog('log-weak-attacker', `Cracker Error: ${err.message}`, 'danger');
    }
  });
}

// ==========================================
// 2. KERBEROS STRONG AUTHENTICATION LAB
// ==========================================
function attachKerberosEvents() {
  // Step 1: AS-REQ / AS-REP
  document.getElementById('btn-krb-step1').addEventListener('click', async () => {
    printLog('log-krb-trace', `[Step 1 AS-REQ] Alice -> Authentication Server (AS): Requesting TGT for realm CORP.ENTERPRISE.LOCAL...`, 'info');

    try {
      const res = await fetch('/api/kerberos/step1-as', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client: 'alice' })
      });
      const data = await res.json();

      if (data.success) {
        printLog('log-krb-trace', `[Step 1 AS-REP] AS -> Alice: Verified client in KDC DB. Generated SessionKey (Kc,tgs) and encrypted TGT.`, 'success');
        printLog('log-krb-trace', `Encrypted TGT Payload (opaque to Alice, encrypted with Ktgs): ${data.asRepEncrypted.ciphertext.substring(0, 36)}...`, 'purple');
        printLog('log-krb-trace', `Alice decrypted AS-REP using password-derived master key Kc. Alice now possesses SessionKey (Kc,tgs)!`, 'info');

        document.getElementById('krb-node-1').classList.add('completed');
        document.getElementById('krb-node-2').classList.add('active');
        document.getElementById('btn-krb-step2').disabled = false;
      }
    } catch (err) {
      printLog('log-krb-trace', `AS-REQ Error: ${err.message}`, 'danger');
    }
  });

  // Step 2: TGS-REQ / TGS-REP
  document.getElementById('btn-krb-step2').addEventListener('click', async () => {
    const service = document.getElementById('krb-service-select').value;
    printLog('log-krb-trace', `[Step 2 TGS-REQ] Alice -> Ticket Granting Server (TGS): Presenting TGT + Authenticator (timestamp) for '${service}'...`, 'info');

    try {
      const res = await fetch('/api/kerberos/step2-tgs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service })
      });
      const data = await res.json();

      if (data.success) {
        printLog('log-krb-trace', `[Step 2 TGS-REP] TGS decrypted TGT with Ktgs, verified Authenticator timestamp freshness.`, 'success');
        printLog('log-krb-trace', `TGS generated Service Session Key (Kc,service) and issued Service Ticket (ST) encrypted with Kv!`, 'success');
        printLog('log-krb-trace', `Service Ticket: ${data.tgsRepEncrypted.ciphertext.substring(0, 36)}...`, 'purple');

        document.getElementById('krb-node-2').classList.add('completed');
        document.getElementById('krb-node-3').classList.add('active');
        document.getElementById('btn-krb-step3').disabled = false;
        document.getElementById('btn-krb-replay-attack').disabled = false;
      }
    } catch (err) {
      printLog('log-krb-trace', `TGS-REQ Error: ${err.message}`, 'danger');
    }
  });

  // Step 3: AP-REQ / AP-REP (Mutual Authentication)
  document.getElementById('btn-krb-step3').addEventListener('click', async () => {
    const service = document.getElementById('krb-service-select').value;
    printLog('log-krb-trace', `[Step 3 AP-REQ] Alice -> Application Server: Presenting Service Ticket + Service Authenticator...`, 'info');

    try {
      const res = await fetch('/api/kerberos/step3-ap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service })
      });
      const data = await res.json();

      if (data.success) {
        printLog('log-krb-trace', `[Step 3 AP-REP] Application Server decrypted ST using Kv and verified Authenticator with Kc,service.`, 'success');
        printLog('log-krb-trace', `MUTUAL AUTHENTICATION ESTABLISHED: Server returned (Timestamp + 1) confirmation!`, 'success');
        printLog('log-krb-trace', `Confidential Resource Released: "${data.grantedResource.confidentialData}"`, 'purple');

        document.getElementById('krb-node-3').classList.add('completed');
      }
    } catch (err) {
      printLog('log-krb-trace', `AP-REQ Error: ${err.message}`, 'danger');
    }
  });

  // KERBEROS ATTACK: Replay AP-REQ (Demonstrates Replay Protection)
  document.getElementById('btn-krb-replay-attack').addEventListener('click', async () => {
    printLog('log-krb-trace', `[ATTACK INTERCEPTION] Eve sniffed Alice's AP-REQ from the wire and attempts a REPLAY ATTACK to Application Server!`, 'warning');

    try {
      const res = await fetch('/api/kerberos/attack-replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();

      if (data.serverDecision && data.serverDecision.replayAttackDetected) {
        printLog('log-krb-trace', `REPLAY ATTACK THWARTED! ${data.serverDecision.message}`, 'danger');
        printLog('log-krb-trace', `Server Replay Cache Error Code: ${data.serverDecision.errorCode} (RFC 4120)`, 'danger');
        printLog('log-krb-trace', `Conclusion: ${data.conclusion}`, 'success');
      } else {
        printLog('log-krb-trace', `Server output: ${JSON.stringify(data.serverDecision)}`, 'info');
      }
    } catch (err) {
      printLog('log-krb-trace', `Replay simulation error: ${err.message}`, 'danger');
    }
  });
}

// ==========================================
// 3. PKI & MUTUAL TLS (mTLS) LAB
// ==========================================
function attachPKIEvents() {
  // Load Certificates
  loadCertificates();

  // Run mTLS Handshake
  document.getElementById('btn-run-mtls').addEventListener('click', async () => {
    printLog('log-pki-trace', `Initiating RFC 8446 / TLS 1.3 Mutual TLS (mTLS) Zero-Trust Handshake...`, 'info');

    try {
      const res = await fetch('/api/pki/mtls-handshake', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();

      if (data.handshakeSuccess) {
        data.transcript.forEach((step, idx) => {
          setTimeout(() => {
            printLog('log-pki-trace', `[${step.step}] ${step.sender} -> ${step.receiver}`, 'purple');
            if (step.content.serverCertificateValid) {
              printLog('log-pki-trace', `  -> Client verified Server X.509 Certificate with Root CA public key (RSA-SHA256 valid).`, 'success');
            }
            if (step.content.proofOfPossessionVerified) {
              printLog('log-pki-trace', `  -> Server verified Client Certificate and Proof-of-Possession signature!`, 'success');
            }
            if (step.content.status) {
              printLog('log-pki-trace', `mTLS CONNECTION SECURED! Master Session Key (AES-256): ${data.sessionKey.substring(0, 32)}...`, 'success');
              printLog('log-pki-trace', `Transmitted Encrypted Payload: ${JSON.stringify(step.content.encryptedSampleTraffic.decryptedVerification.message)}`, 'info');
            }
          }, idx * 250);
        });
      } else {
        printLog('log-pki-trace', `mTLS Handshake Failed at: ${data.failedAtStep}!`, 'danger');
        printLog('log-pki-trace', `Reason: ${data.error}`, 'danger');
      }
    } catch (err) {
      printLog('log-pki-trace', `Handshake Error: ${err.message}`, 'danger');
    }
  });

  // Revoke Client Certificate
  document.getElementById('btn-revoke-cert').addEventListener('click', async () => {
    printLog('log-pki-trace', `Broadcasting Certificate Revocation to CA Certificate Revocation List (CRL)...`, 'warning');

    try {
      const res = await fetch('/api/pki/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Key compromised or employee departed' })
      });
      const data = await res.json();

      printLog('log-pki-trace', `Revoked Certificate Serial: ${data.revokedSerialNumber}`, 'danger');
      printLog('log-pki-trace', `Active CRL entries: ${data.crlSize}. Re-run mTLS handshake to observe immediate security rejection!`, 'warning');
      loadCertificates();
    } catch (err) {
      printLog('log-pki-trace', `Revocation Error: ${err.message}`, 'danger');
    }
  });

  // Re-initialize Root CA
  document.getElementById('btn-reset-ca').addEventListener('click', async () => {
    printLog('log-pki-trace', `Generating fresh Root CA with 2048-bit RSA Key Pair...`, 'info');
    try {
      const res = await fetch('/api/pki/init', { method: 'POST' });
      const data = await res.json();
      printLog('log-pki-trace', `Root CA regenerated: ${data.rootCA.subject} (Serial: ${data.rootCA.serialNumber})`, 'success');
      loadCertificates();
    } catch (err) {
      printLog('log-pki-trace', `Error: ${err.message}`, 'danger');
    }
  });
}

async function loadCertificates() {
  try {
    const res = await fetch('/api/pki/certificates');
    const data = await res.json();

    const certListContainer = document.getElementById('pki-cert-list');
    if (!certListContainer) return;
    certListContainer.innerHTML = '';

    data.certificates.forEach(c => {
      const div = document.createElement('div');
      div.className = 'packet-box';
      div.innerHTML = `
        <div class="packet-header">${c.serialNumber} ${c.isRevoked ? '<span class="badge badge-rose">REVOKED (CRL)</span>' : '<span class="badge badge-emerald">VALID</span>'}</div>
        <div><strong>Subject:</strong> ${c.subject}</div>
        <div><strong>Issuer:</strong> ${c.issuer}</div>
        <div><strong>Validity:</strong> ${new Date(c.validity.notBefore).toLocaleDateString()} - ${new Date(c.validity.notAfter).toLocaleDateString()}</div>
      `;
      certListContainer.appendChild(div);
    });
  } catch (err) {
    console.error('Failed to load certificates:', err);
  }
}

// ==========================================
// 4. COMPARISON MATRIX & ACADEMIC ALIGNMENT
// ==========================================
async function fetchComparisonMatrix() {
  try {
    const res = await fetch('/api/comparison');
    const data = await res.json();
    const tbody = document.getElementById('comparison-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    data.comparisonMatrix.forEach(row => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${row.criterion}</strong></td>
        <td style="color: #fb7185;">${row.weakAuth}</td>
        <td style="color: #38bdf8;">${row.kerberos}</td>
        <td style="color: #34d399;">${row.pki}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed to load comparison:', err);
  }
}

