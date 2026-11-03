// test_all.js - Unit and integration tests for all cryptographic and security modules
const { WEAK_USER_DB, weakLoginPlaintext, accessWeakResource } = require('./src/crypto/weakAuth');
const { simulateSniffingAttack, simulateReplayAttack, simulateDictionaryCrack } = require('./src/crypto/attacks');
const { KerberosKDC, encryptAES, decryptAES } = require('./src/crypto/kerberos');
const { PKIEngine, generateRSAKeyPair } = require('./src/crypto/pki');

console.log('====================================================');
console.log('CNS SECURITY SUITE: AUTOMATED MODULE TEST VERIFICATION');
console.log('====================================================');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`[PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`[FAIL] ${message}`);
    process.exitCode = 1;
  }
}

// 1. Weak Auth Tests
console.log('\n--- 1. Testing Weak Authentication & Attack Modules ---');
const loginRes = weakLoginPlaintext('alice', 'password123');
assert(loginRes.success === true, 'Weak login succeeds with valid credentials');
assert(typeof loginRes.token === 'string', 'Weak login issues token');

// Attack 1: Sniffing
const sniffRes = simulateSniffingAttack(loginRes.packetTrace);
assert(sniffRes.hijackSuccess === true, 'Sniffing attack intercepts and extracts credentials');
assert(sniffRes.extractedCredentials.username === 'alice', 'Sniffed username matches victim');
assert(sniffRes.extractedCredentials.password === 'password123', 'Sniffed password matches victim');

// Attack 2: Replay Attack on Weak Auth
const replayRes = simulateReplayAttack(loginRes.token, 'unauthorized_wire_transfer');
assert(replayRes.serverAccepted === true, 'Weak server is vulnerable to token replay');
assert(replayRes.serverOutput.data.actionExecuted === 'unauthorized_wire_transfer', 'Attacker executed unauthorized action via replay');

// Attack 3: Dictionary Cracking on MD5
const crackRes = simulateDictionaryCrack('482c811da5d5b4bc6d497ffa98491e38', 'md5');
assert(crackRes.cracked === true, 'Dictionary attack cracked MD5 hash');
assert(crackRes.crackedPassword === 'password123', 'Cracked password matches original plaintext');

// 2. Kerberos Protocol Tests
console.log('\n--- 2. Testing Kerberos v5 (RFC 4120) Implementation ---');
const kdc = new KerberosKDC();

// AS Exchange
const asRes = kdc.processASReq('alice');
assert(asRes.asRepEncrypted !== null, 'AS-REQ successfully generates AS-REP');
assert(asRes.debugInfo.tgtEncryptedEnvelope !== null, 'TGT generated and encrypted with Ktgs');

// TGS Exchange
const clientAuthTGS = encryptAES(asRes.debugInfo.sessionKey_C_TGS, { client: 'alice', timestamp: Date.now() });
const tgsRes = kdc.processTGSReq(asRes.debugInfo.tgtEncryptedEnvelope, clientAuthTGS, 'fileserver/hr-records');
assert(tgsRes.tgsRepEncrypted !== null, 'TGS-REQ successfully generates TGS-REP');
assert(tgsRes.debugInfo.serviceTicketEncrypted !== null, 'Service Ticket generated and encrypted with Kv');

// AP Exchange (Mutual Auth)
const clientTimestamp = Date.now();
const clientAuthAP = encryptAES(tgsRes.debugInfo.sessionKey_C_Service, { client: 'alice', timestamp: clientTimestamp });
const apRes = kdc.processAPReq(tgsRes.debugInfo.serviceTicketEncrypted, clientAuthAP, 'fileserver/hr-records');
assert(apRes.success === true, 'AP-REQ successfully authenticates client to application server');
assert(apRes.mutualAuthenticationVerified === true, 'Mutual authentication confirmed');

// Kerberos Replay Defense Test
const replayAP = kdc.processAPReq(tgsRes.debugInfo.serviceTicketEncrypted, clientAuthAP, 'fileserver/hr-records');
assert(replayAP.success === false, 'Kerberos successfully BLOCKS replay attack');
assert(replayAP.errorCode === 'KRB_AP_ERR_REPEAT', 'Kerberos returns KRB_AP_ERR_REPEAT on duplicate timestamp');

// 3. PKI & Mutual TLS (mTLS) Tests
console.log('\n--- 3. Testing Public Key Infrastructure (PKI) & mTLS ---');
const pki = new PKIEngine();
assert(pki.rootCA !== null, 'Root CA initialized with self-signed certificate');

const serverKeys = generateRSAKeyPair();
const serverCSR = pki.createCSR('CN=secure.server.corp', serverKeys);
const serverCert = pki.issueCertificate(serverCSR, ['Digital Signature', 'Key Encipherment']);
assert(serverCert.serialNumber !== null, 'CA issues valid Server Digital Certificate');

const clientKeys = generateRSAKeyPair();
const clientCSR = pki.createCSR('CN=alice@corp.local', clientKeys);
const clientCert = pki.issueCertificate(clientCSR, ['Digital Signature', 'Client Authentication']);
assert(clientCert.serialNumber !== null, 'CA issues valid Client Digital Certificate');

// Verify certificates
const verifyServer = pki.verifyCertificate(serverCert);
assert(verifyServer.valid === true, 'Server certificate verifies cryptographically against Root CA');

const verifyClient = pki.verifyCertificate(clientCert);
assert(verifyClient.valid === true, 'Client certificate verifies cryptographically against Root CA');

// Run mTLS Handshake
const mtlsRes = pki.simulateMTLSHandshake(clientKeys, clientCert, serverKeys, serverCert);
assert(mtlsRes.handshakeSuccess === true, 'Mutual TLS 1.3 handshake establishes encrypted tunnel');
assert(typeof mtlsRes.sessionKey === 'string', 'Symmetric master session key derived');

// Test Revocation (CRL)
pki.revokeCertificate(clientCert.serialNumber, 'Key compromised');
const mtlsRevokedRes = pki.simulateMTLSHandshake(clientKeys, clientCert, serverKeys, serverCert);
assert(mtlsRevokedRes.handshakeSuccess === false, 'mTLS handshake fails when certificate is revoked');
assert(mtlsRevokedRes.error.includes('CERTIFICATE_REVOKED'), 'Error correctly identifies revoked certificate');

console.log('\n====================================================');
console.log(`TOTAL TESTS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${totalTests - passedTests}`);
console.log('====================================================');

