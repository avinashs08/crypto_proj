// server.js - Zero-dependency Node.js HTTP Server & REST API for CNS Security Suite
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const { WEAK_USER_DB, activeWeakTokens, weakLoginPlaintext, accessWeakResource } = require('./src/crypto/weakAuth');
const { COMMON_DICTIONARY, simulateSniffingAttack, simulateReplayAttack, simulateDictionaryCrack } = require('./src/crypto/attacks');
const { KDC_SECRETS, serverReplayCache, KerberosKDC, encryptAES, decryptAES } = require('./src/crypto/kerberos');
const { PKIEngine, generateRSAKeyPair } = require('./src/crypto/pki');

const PORT = process.env.PORT || 3000;

// Initialize Singletons
const kdcInstance = new KerberosKDC();
const pkiInstance = new PKIEngine();

// Pre-generate standard PKI actors for quick demonstration
let serverKeyPair = generateRSAKeyPair();
let serverCSR = pkiInstance.createCSR('CN=secure-corp-fileserver.local, O=Enterprise Infrastructure, C=US', serverKeyPair);
let serverCert = pkiInstance.issueCertificate(serverCSR, ['Digital Signature', 'Key Encipherment']);

let clientKeyPair = generateRSAKeyPair();
let clientCSR = pkiInstance.createCSR('CN=alice@corp.local, O=Human Resources, C=US', clientKeyPair);
let clientCert = pkiInstance.issueCertificate(clientCSR, ['Digital Signature', 'Client Authentication']);

// State tracking for Kerberos workflow demo
let currentKerberosSession = {
  tgtEncrypted: null,
  sessionKey_C_TGS: null,
  serviceTicketEncrypted: null,
  sessionKey_C_Service: null,
  lastAPReq: null,
  capturedByAttacker: null
};

// MIME types for static files
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e6) { // 1MB limit
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  try {
    // API ROUTES
    if (pathname.startsWith('/api/')) {
      // 1. System Status
      if (pathname === '/api/status' && req.method === 'GET') {
        return sendJSON(res, 200, {
          status: 'ONLINE',
          cryptoEngine: 'Node.js Cryptographic Subsystem (FIPS-compliant primitives)',
          weakAuth: {
            registeredUsers: Object.keys(WEAK_USER_DB),
            activeTokensCount: activeWeakTokens.size
          },
          kerberos: {
            realm: 'CORP.ENTERPRISE.LOCAL',
            configuredServices: Object.keys(KDC_SECRETS.services),
            replayCacheEntries: serverReplayCache.size,
            hasActiveTGT: !!currentKerberosSession.tgtEncrypted,
            hasActiveServiceTicket: !!currentKerberosSession.serviceTicketEncrypted
          },
          pki: {
            rootCASubject: pkiInstance.rootCA.certificate.subject,
            issuedCertsCount: pkiInstance.issuedCertificates.size,
            revokedCertsCount: pkiInstance.certificateRevocationList.size
          }
        });
      }

      // 2. WEAK AUTH: Login
      if (pathname === '/api/weak-auth/login' && req.method === 'POST') {
        const body = await parseBody(req);
        const username = body.username || 'alice';
        const password = body.password || 'password123';
        const result = weakLoginPlaintext(username, password);
        return sendJSON(res, result.success ? 200 : 401, result);
      }

      // 3. WEAK AUTH: Resource Access
      if (pathname === '/api/weak-auth/access' && req.method === 'POST') {
        const body = await parseBody(req);
        const result = accessWeakResource(body.token, body.action || 'view_balance');
        return sendJSON(res, result.statusCode, result);
      }

      // 4. WEAK AUTH ATTACK: Sniffing
      if (pathname === '/api/weak-auth/attack-sniff' && req.method === 'POST') {
        const body = await parseBody(req);
        const samplePacket = body.packet || {
          wireData: `POST /auth/basic HTTP/1.1\r\nHost: insecure-server.corp\r\nAuthorization: Basic ${Buffer.from('alice:password123').toString('base64')}\r\n\r\n{"username":"alice","password":"password123"}`
        };
        const attackResult = simulateSniffingAttack(samplePacket);
        return sendJSON(res, 200, attackResult);
      }

      // 5. WEAK AUTH ATTACK: Replay
      if (pathname === '/api/weak-auth/attack-replay' && req.method === 'POST') {
        const body = await parseBody(req);
        // If no token passed, get first active or create one
        let token = body.token;
        if (!token) {
          const firstEntry = activeWeakTokens.keys().next();
          if (!firstEntry.done) {
            token = firstEntry.value;
          } else {
            // Log in alice to generate a token
            const login = weakLoginPlaintext('alice', 'password123');
            token = login.token;
          }
        }
        const replayResult = simulateReplayAttack(token, body.action || 'unauthorized_fund_transfer_100000');
        return sendJSON(res, 200, replayResult);
      }

      // 6. WEAK AUTH ATTACK: Dictionary Cracking
      if (pathname === '/api/weak-auth/attack-crack' && req.method === 'POST') {
        const body = await parseBody(req);
        const targetHash = body.hash || WEAK_USER_DB['alice'].passwordHashMD5;
        const crackResult = simulateDictionaryCrack(targetHash, body.algorithm || 'md5');
        return sendJSON(res, 200, crackResult);
      }

      // 7. KERBEROS: Step 1 AS-REQ & AS-REP
      if (pathname === '/api/kerberos/step1-as' && req.method === 'POST') {
        const body = await parseBody(req);
        const client = body.client || 'alice';
        const asResult = kdcInstance.processASReq(client);

        // Store in demo session
        currentKerberosSession.tgtEncrypted = asResult.debugInfo.tgtEncryptedEnvelope;
        currentKerberosSession.sessionKey_C_TGS = asResult.debugInfo.sessionKey_C_TGS;

        return sendJSON(res, 200, {
          stepName: 'AS-REQ / AS-REP (Authentication Server Exchange)',
          success: true,
          client: client,
          realm: 'CORP.ENTERPRISE.LOCAL',
          asRepEncrypted: asResult.asRepEncrypted,
          explanation: 'KDC verified user existence, generated Session Key (Kc,tgs), created Ticket Granting Ticket (TGT) encrypted with TGS secret key, and returned AS-REP encrypted with Alice master key (derived from password).',
          packetWireView: {
            request: `AS-REQ: Client=${client}, Service=krbtgt/CORP.ENTERPRISE.LOCAL, Nonce=0x8fa37b`,
            response: `AS-REP: EncryptedWith(Kc) [SessionKey_C_TGS, TGT=EncryptedWith(Ktgs)]`
          },
          inspector: asResult.debugInfo
        });
      }

      // 8. KERBEROS: Step 2 TGS-REQ & TGS-REP
      if (pathname === '/api/kerberos/step2-tgs' && req.method === 'POST') {
        const body = await parseBody(req);
        const service = body.service || 'fileserver/hr-records';

        if (!currentKerberosSession.tgtEncrypted || !currentKerberosSession.sessionKey_C_TGS) {
          // Auto run step 1 first for smooth experience
          const asRes = kdcInstance.processASReq('alice');
          currentKerberosSession.tgtEncrypted = asRes.debugInfo.tgtEncryptedEnvelope;
          currentKerberosSession.sessionKey_C_TGS = asRes.debugInfo.sessionKey_C_TGS;
        }

        // Client builds Authenticator encrypted with SessionKey_C_TGS
        const clientAuthenticator = {
          client: 'alice',
          timestamp: Date.now(),
          subKey: 'OPTIONAL_SUBKEY_FOR_INTEGRITY'
        };
        const encryptedAuthenticator = encryptAES(currentKerberosSession.sessionKey_C_TGS, clientAuthenticator);

        const tgsResult = kdcInstance.processTGSReq(
          currentKerberosSession.tgtEncrypted,
          encryptedAuthenticator,
          service
        );

        currentKerberosSession.serviceTicketEncrypted = tgsResult.debugInfo.serviceTicketEncrypted;
        currentKerberosSession.sessionKey_C_Service = tgsResult.debugInfo.sessionKey_C_Service;

        return sendJSON(res, 200, {
          stepName: 'TGS-REQ / TGS-REP (Ticket Granting Service Exchange)',
          success: true,
          service: service,
          tgsRepEncrypted: tgsResult.tgsRepEncrypted,
          explanation: 'TGS decrypted TGT using Ktgs, verified Authenticator timestamp, generated Service Session Key (Kc,service), and issued Service Ticket (ST) encrypted with Service Secret Key (Kv).',
          packetWireView: {
            request: `TGS-REQ: [TGT=EncryptedWith(Ktgs), Authenticator=EncryptedWith(Kc,tgs), Service=${service}]`,
            response: `TGS-REP: EncryptedWith(Kc,tgs) [SessionKey_C_Service, ServiceTicket=EncryptedWith(Kv)]`
          },
          inspector: tgsResult.debugInfo
        });
      }

      // 9. KERBEROS: Step 3 AP-REQ & AP-REP (Mutual Authentication)
      if (pathname === '/api/kerberos/step3-ap' && req.method === 'POST') {
        const body = await parseBody(req);
        const service = body.service || 'fileserver/hr-records';

        if (!currentKerberosSession.serviceTicketEncrypted || !currentKerberosSession.sessionKey_C_Service) {
          // Pre-populate steps 1 and 2
          const asRes = kdcInstance.processASReq('alice');
          currentKerberosSession.tgtEncrypted = asRes.debugInfo.tgtEncryptedEnvelope;
          currentKerberosSession.sessionKey_C_TGS = asRes.debugInfo.sessionKey_C_TGS;

          const auth = encryptAES(currentKerberosSession.sessionKey_C_TGS, { client: 'alice', timestamp: Date.now() });
          const tgsRes = kdcInstance.processTGSReq(currentKerberosSession.tgtEncrypted, auth, service);
          currentKerberosSession.serviceTicketEncrypted = tgsRes.debugInfo.serviceTicketEncrypted;
          currentKerberosSession.sessionKey_C_Service = tgsRes.debugInfo.sessionKey_C_Service;
        }

        const now = Date.now();
        // Client builds Service Authenticator
        const serviceAuthenticator = {
          client: 'alice',
          timestamp: now,
          nonce: crypto.randomBytes(4).toString('hex')
        };
        const encryptedAuth = encryptAES(currentKerberosSession.sessionKey_C_Service, serviceAuthenticator);

        // Store AP-REQ for potential replay attack simulation
        currentKerberosSession.lastAPReq = {
          serviceTicket: currentKerberosSession.serviceTicketEncrypted,
          authenticator: encryptedAuth,
          service: service,
          originalTimestamp: now
        };

        const apResult = kdcInstance.processAPReq(
          currentKerberosSession.serviceTicketEncrypted,
          encryptedAuth,
          service
        );

        return sendJSON(res, apResult.success ? 200 : 400, {
          stepName: 'AP-REQ / AP-REP (Mutual Application Server Authentication)',
          ...apResult,
          explanation: 'Application Server decrypted Service Ticket using Kv, extracted Kc,service, decrypted Authenticator, recorded (client, timestamp) in Replay Cache, and responded with timestamp + 1 to confirm mutual identity!',
          packetWireView: {
            request: `AP-REQ: [ServiceTicket=EncryptedWith(Kv), Authenticator=EncryptedWith(Kc,service)]`,
            response: `AP-REP: EncryptedWith(Kc,service) [Timestamp+1 (${now + 1})] -> PROVING MUTUAL AUTHENTICATION`
          }
        });
      }

      // 10. KERBEROS ATTACK: Replay Attempt (Demonstrates Kerberos Defense)
      if (pathname === '/api/kerberos/attack-replay' && req.method === 'POST') {
        if (!currentKerberosSession.lastAPReq) {
          // Run Step 3 once so there is a legitimate packet to sniff
          const asRes = kdcInstance.processASReq('alice');
          currentKerberosSession.tgtEncrypted = asRes.debugInfo.tgtEncryptedEnvelope;
          currentKerberosSession.sessionKey_C_TGS = asRes.debugInfo.sessionKey_C_TGS;
          const auth1 = encryptAES(currentKerberosSession.sessionKey_C_TGS, { client: 'alice', timestamp: Date.now() });
          const tgsRes = kdcInstance.processTGSReq(currentKerberosSession.tgtEncrypted, auth1, 'fileserver/hr-records');
          currentKerberosSession.serviceTicketEncrypted = tgsRes.debugInfo.serviceTicketEncrypted;
          currentKerberosSession.sessionKey_C_Service = tgsRes.debugInfo.sessionKey_C_Service;

          const now = Date.now();
          const auth2 = encryptAES(currentKerberosSession.sessionKey_C_Service, { client: 'alice', timestamp: now });
          kdcInstance.processAPReq(currentKerberosSession.serviceTicketEncrypted, auth2, 'fileserver/hr-records');
          currentKerberosSession.lastAPReq = {
            serviceTicket: currentKerberosSession.serviceTicketEncrypted,
            authenticator: auth2,
            service: 'fileserver/hr-records',
            originalTimestamp: now
          };
        }

        // ATTACKER SNIFFED AP-REQ AND REPLAYS IT TO THE SERVER!
        const replayedPacket = currentKerberosSession.lastAPReq;
        const serverCheck = kdcInstance.processAPReq(
          replayedPacket.serviceTicket,
          replayedPacket.authenticator,
          replayedPacket.service
        );

        return sendJSON(res, 200, {
          attackSimulation: 'Kerberos Replay Attack Interception',
          attackerRole: 'Eve / Mallory',
          sniffedPacket: {
            serviceTicket: '[ENCRYPTED_SERVICE_TICKET_HEX_ENVELOPE]',
            authenticator: '[ENCRYPTED_AUTHENTICATOR_CONTAINING_TIMESTAMP]'
          },
          replayedAt: new Date().toISOString(),
          serverDecision: serverCheck,
          defenseMechanism: 'Timestamp Window Verification + Server Replay Cache (KRB_AP_ERR_REPEAT)',
          conclusion: 'Unlike Weak Authentication (which allowed replay), Kerberos detected the duplicate timestamp in its replay cache and rejected the attacker packet!'
        });
      }

      // 11. PKI: Initialize / Reset CA
      if (pathname === '/api/pki/init' && req.method === 'POST') {
        const rootCert = pkiInstance.initRootCA();
        return sendJSON(res, 200, {
          success: true,
          message: 'Root Certificate Authority initialized with fresh 2048-bit RSA Key Pair.',
          rootCA: rootCert
        });
      }

      // 12. PKI: Inspect Certificates
      if (pathname === '/api/pki/certificates' && req.method === 'GET') {
        const certList = [];
        for (const [serial, cert] of pkiInstance.issuedCertificates.entries()) {
          certList.push({
            serialNumber: serial,
            subject: cert.subject,
            issuer: cert.issuer,
            isCA: cert.isCA,
            validity: cert.validity,
            isRevoked: pkiInstance.certificateRevocationList.has(serial)
          });
        }
        return sendJSON(res, 200, {
          rootCA: pkiInstance.rootCA.certificate,
          certificates: certList,
          crlCount: pkiInstance.certificateRevocationList.size
        });
      }

      // 13. PKI: Full Mutual TLS (mTLS) Handshake
      if (pathname === '/api/pki/mtls-handshake' && req.method === 'POST') {
        const handshakeResult = pkiInstance.simulateMTLSHandshake(
          clientKeyPair,
          clientCert,
          serverKeyPair,
          serverCert
        );
        return sendJSON(res, handshakeResult.handshakeSuccess ? 200 : 400, handshakeResult);
      }

      // 14. PKI: Revoke Certificate
      if (pathname === '/api/pki/revoke' && req.method === 'POST') {
        const body = await parseBody(req);
        const serial = body.serialNumber || clientCert.serialNumber;
        const reason = body.reason || 'Private key compromise reported';
        const revocation = pkiInstance.revokeCertificate(serial, reason);
        return sendJSON(res, 200, revocation);
      }

      // 15. Architectural Comparison Matrix
      if (pathname === '/api/comparison' && req.method === 'GET') {
        return sendJSON(res, 200, {
          comparisonMatrix: [
            {
              criterion: 'Cryptographic Foundation',
              weakAuth: 'None or Weak Unsalted Hashes (Plaintext, MD5, SHA-1)',
              kerberos: 'Symmetric Cryptography (AES-256-GCM, PBKDF2 Master Keys)',
              pki: 'Asymmetric Cryptography (RSA-2048 / ECC-384, X.509 Certificates, SHA-256)'
            },
            {
              criterion: 'Replay Attack Immunity',
              weakAuth: 'VULNERABLE (Static tokens & credentials can be replayed freely)',
              kerberos: 'IMMUNE (Timestamp skew window $\\pm 5$ min + Server Replay Cache)',
              pki: 'IMMUNE (Fresh random nonces, digital signatures per handshake, ephemeral keys)'
            },
            {
              criterion: 'Mutual Authentication',
              weakAuth: 'NO (Client sends password blindly to potentially fake server)',
              kerberos: 'YES (AP-REP provides proof of server possession of session key)',
              pki: 'YES (Mutual TLS validates both Server Certificate and Client Certificate)'
            },
            {
              criterion: 'Network Sniffing Resistance',
              weakAuth: 'VULNERABLE (Credentials captured in cleartext via Wireshark)',
              kerberos: 'IMMUNE (Password never sent across wire; only encrypted tickets)',
              pki: 'IMMUNE (Full asymmetric key exchange establishes AES-256 encrypted tunnel)'
            },
            {
              criterion: 'Single Point of Failure',
              weakAuth: 'Single auth database vulnerable to leaks and offline cracking',
              kerberos: 'Key Distribution Center (KDC) must be online for ticket issuance',
              pki: 'Decentralized (Root CA can be kept offline; certs verified via public keys)'
            },
            {
              criterion: 'Scalability & Trust Boundary',
              weakAuth: 'Very poor; hardcoded secrets and shared tables',
              kerberos: 'Ideal for homogeneous enterprise domains (Windows Active Directory)',
              pki: 'Global Internet scale (Web PKI, TLS, mTLS, Zero-Trust Architecture)'
            },
            {
              criterion: 'Computational Overhead',
              weakAuth: 'Negligible (No crypto)',
              kerberos: 'Extremely fast (Hardware-accelerated AES symmetric encryption)',
              pki: 'Moderate initial handshake (RSA/ECC modular arithmetic), fast symmetric session'
            }
          ]
        });
      }

      // 16. Academic Course Outcome (PO) & SDG Mapping
      if (pathname === '/api/academic-mapping' && req.method === 'GET') {
        return sendJSON(res, 200, {
          programOutcomes: {
            PO3: {
              title: 'Design/Development of Solutions',
              contribution: 'Engineered multi-tier authentication protocols resilient against eavesdropping, token replay, and tampering. Designed ticket grant state machines and certificate validation logic.'
            },
            PO5: {
              title: 'Modern Tool Usage',
              contribution: 'Utilized state-of-the-art cryptographic subsystems (Node.js crypto, RSA-2048, AES-256-GCM, SHA-256, HMAC), packet inspection tools, and full-stack interactive simulations.'
            },
            PO7: {
              title: 'Environment and Sustainability',
              contribution: 'Analyzed computational power and CPU cycle efficiency between symmetric (Kerberos) and asymmetric (PKI) cryptography, optimizing cryptographic workload energy footprint.'
            },
            PO8: {
              title: 'Ethics',
              contribution: 'Demonstrated offensive attack simulations strictly within a controlled sandbox to comprehend cyber threat vectors and design defensive countermeasures protecting human data privacy.'
            },
            PSO2: {
              title: 'Program Specific Outcome (CNS Specialization)',
              contribution: 'Implemented real RFC 4120 Kerberos ticket issuance, X.509 digital certificate signing, CRL revocation checking, and mutual TLS (mTLS) zero-trust secure pipelines.'
            }
          },
          sustainableDevelopmentGoals: {
            SDG4: {
              title: 'Quality Education',
              contribution: 'Provides an open-source, interactive, visual laboratory for cybersecurity education, demystifying abstract mathematical and protocol concepts into tangible demonstrations.'
            },
            SDG9: {
              title: 'Industry, Innovation, and Infrastructure',
              contribution: 'Strengthens cybersecurity resilience for industrial ICT systems, enterprise cloud networks, and critical national infrastructure against credential theft and unauthorized access.'
            }
          }
        });
      }

      // Not found API route
      return sendJSON(res, 404, { error: 'API route not found' });
    }

    // STATIC FILE SERVING
    let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
    
    // Security check: prevent directory traversal
    if (!filePath.startsWith(path.join(__dirname, 'public'))) {
      res.writeHead(403);
      return res.end('Access Denied');
    }

    fs.readFile(filePath, (err, content) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
        } else {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error: ' + err.message);
        }
      } else {
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(content);
      }
    });

  } catch (error) {
    console.error('Unhandled server error:', error);
    sendJSON(res, 500, { error: 'Internal Server Error', message: error.message });
  }
});

server.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(` Cryptography & Network Security Lab Platform`);
  console.log(` Real-Life Implementation: Weak Auth Attacks vs Kerberos & PKI`);
  console.log(` Server active at: http://localhost:${PORT}`);
  console.log(` Academic Mapping: PO3, PO5, PO7, PO8, PSO2 | SDG 4 & SDG 9`);
  console.log(`================================================================`);
});

