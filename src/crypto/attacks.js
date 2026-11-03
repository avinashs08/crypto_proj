// src/crypto/attacks.js
// Attack Simulation Engine for Weak Authentication
const crypto = require('crypto');
const { WEAK_USER_DB, activeWeakTokens, accessWeakResource } = require('./weakAuth');

// Built-in attack wordlist / dictionary for cracking simulation
const COMMON_DICTIONARY = [
  '123456', 'password', '12345678', 'qwerty', '123456789',
  'admin', 'welcome', 'login', 'password123', 'admin2024',
  'crypto101', 'secret', 'football', 'master', 'dragon'
];

/**
 * ATTACK 1: Packet Sniffing / Eavesdropping
 * Simulates a Promiscuous Network Sniffer (like Wireshark / tcpdump) on an unencrypted network segment.
 * Intercepts unencrypted plaintext or Basic Auth HTTP headers.
 */
function simulateSniffingAttack(capturedPacket) {
  const result = {
    attackName: 'Network Packet Sniffing & Eavesdropping',
    vulnerability: 'Unencrypted Transmission (CWE-319: Cleartext Transmission of Sensitive Information)',
    timestamp: new Date().toISOString(),
    sniffedRaw: capturedPacket.wireData || JSON.stringify(capturedPacket),
    extractedCredentials: null,
    hijackSuccess: false
  };

  // Inspect headers for Authorization: Basic <base64>
  const authHeader = capturedPacket.headers && capturedPacket.headers['Authorization'];
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Part = authHeader.replace('Basic ', '');
    const decoded = Buffer.from(base64Part, 'base64').toString('utf8');
    const [user, pass] = decoded.split(':');
    result.extractedCredentials = {
      method: 'HTTP Basic Auth Base64 Decoding',
      username: user,
      password: pass,
      note: 'Base64 is an encoding scheme, NOT encryption! Anyone on the network wire can reverse it instantly.'
    };
    result.hijackSuccess = true;
  } else if (capturedPacket.payload && capturedPacket.payload.username && capturedPacket.payload.password) {
    result.extractedCredentials = {
      method: 'Cleartext JSON extraction',
      username: capturedPacket.payload.username,
      password: capturedPacket.payload.password,
      note: 'Credentials were sent in plain JSON body without TLS.'
    };
    result.hijackSuccess = true;
  }

  return result;
}

/**
 * ATTACK 2: Replay Attack
 * Attacker captures a valid authentication token off the wire and replays it later.
 * Because the weak server does not use timestamps, nonces, or mutual challenges,
 * the attacker gains full unauthorized access without ever needing the victim's password!
 */
function simulateReplayAttack(capturedToken, targetAction = 'transfer_funds') {
  const captureTime = new Date().toISOString();

  // Attacker intercepts token:
  const isTokenActive = activeWeakTokens.has(capturedToken);

  if (!isTokenActive) {
    return {
      attackName: 'Token Replay Attack',
      success: false,
      error: 'No active token captured or token invalid',
      targetAction
    };
  }

  const victimSession = activeWeakTokens.get(capturedToken);

  // Attacker 'Eve' crafts a forged HTTP request reusing the stolen token
  const forgedRequestHeaders = {
    'Host': 'insecure-server.corp',
    'User-Agent': 'Mozilla/5.0 (Kali-Linux-Attacker; rv:109.0)',
    'Authorization': `Bearer ${capturedToken}`,
    'X-Attacker-Identity': 'Eve-Mallory',
    'X-Action': targetAction
  };

  // Vulnerable server processes the request:
  const serverResponse = accessWeakResource(capturedToken, targetAction);

  return {
    attackName: 'Session / Token Replay Attack',
    vulnerability: 'Missing Nonce / Replay Protection (CWE-294: Authentication Bypass by Capture-replay)',
    victimUser: victimSession.username,
    attackerIdentity: 'Eve (Malicious Intermediary)',
    capturedToken: capturedToken,
    capturedTime: captureTime,
    replayedTime: new Date(Date.now() + 15000).toISOString(), // Replayed 15 seconds later
    forgedRequestHeaders: forgedRequestHeaders,
    serverAccepted: serverResponse.success,
    impact: serverResponse.success
      ? `CRITICAL EXPLOIT: Server accepted replayed token! Attacker executed unauthorized action '${targetAction}' on behalf of ${victimSession.username} without knowing password.`
      : 'Attack blocked.',
    serverOutput: serverResponse
  };
}

/**
 * ATTACK 3: Fast Dictionary / Rainbow Table Attack on Leaked Hash
 * Demonstrates the catastrophic weakness of unsalted MD5 / SHA-1 hashes.
 */
function simulateDictionaryCrack(targetHash, hashType = 'md5') {
  const startTime = process.hrtime.bigint();
  let crackedPassword = null;
  let attempts = 0;

  for (const word of COMMON_DICTIONARY) {
    attempts++;
    const computedHash = crypto.createHash(hashType).update(word).digest('hex');
    if (computedHash.toLowerCase() === targetHash.toLowerCase()) {
      crackedPassword = word;
      break;
    }
  }

  const endTime = process.hrtime.bigint();
  const durationMicroseconds = Number(endTime - startTime) / 1000;

  // Comparison with Salted PBKDF2
  const secureSalt = crypto.randomBytes(16).toString('hex');
  const secureHash = crypto.pbkdf2Sync(crackedPassword || 'password123', secureSalt, 100000, 32, 'sha256').toString('hex');

  return {
    attackName: 'Dictionary & Rainbow Table Cryptanalysis',
    vulnerability: 'Use of a Broken or Risky Cryptographic Algorithm (CWE-327: MD5 Unsalted Hashing)',
    targetHash: targetHash,
    hashAlgorithm: hashType.toUpperCase(),
    totalDictionaryEntriesChecked: attempts,
    cracked: crackedPassword !== null,
    crackedPassword: crackedPassword,
    timeTakenMicroseconds: durationMicroseconds.toFixed(2),
    speedAssessment: 'Instantaneous (< 1 millisecond on modern CPU; billions of hashes/sec on GPU)',
    mitigationDemonstration: {
      recommendation: 'Salted PBKDF2 / Argon2 / bcrypt with high work factor (100,000+ iterations)',
      sampleSalt: secureSalt,
      samplePBKDF2Hash: secureHash,
      reason: 'Unique salt destroys precomputed rainbow tables; key derivation iteration count makes brute-force computationally prohibitive.'
    }
  };
}

module.exports = {
  COMMON_DICTIONARY,
  simulateSniffingAttack,
  simulateReplayAttack,
  simulateDictionaryCrack
};

