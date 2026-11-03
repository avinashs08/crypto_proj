// src/crypto/kerberos.js
// Industrial & Educational Implementation of Kerberos v5 Protocol (RFC 4120)
const crypto = require('crypto');

/**
 * Symmetric AES-256-GCM helper for ticket and authenticator encryption
 */
function encryptAES(key, plaintextObj) {
  // Ensure key is 32 bytes (derive if string)
  const keyBuffer = crypto.createHash('sha256').update(key).digest();
  const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  
  const jsonStr = JSON.stringify(plaintextObj);
  let encrypted = cipher.update(jsonStr, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted,
    authTag: authTag
  };
}

function decryptAES(key, envelope) {
  try {
    const keyBuffer = crypto.createHash('sha256').update(key).digest();
    const iv = Buffer.from(envelope.iv, 'hex');
    const authTag = Buffer.from(envelope.authTag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(envelope.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (err) {
    throw new Error('Decryption failed or ciphertext corrupted/tampered: ' + err.message);
  }
}

// Master secret keys stored in the Key Distribution Center (KDC)
const KDC_SECRETS = {
  // Secret key shared only between KDC Authentication Service & Ticket Granting Service
  kdcMasterKey: 'KDC_TOP_SECRET_MASTER_KEY_2026_AES256',
  // Secret key of the TGS itself
  tgsKey: 'TGS_SERVICE_KEY_32_BYTES_STRONG_SECRET',
  // Service secrets known only to KDC and the respective Application Server
  services: {
    'fileserver/hr-records': {
      serviceName: 'HR Fileserver (Financial & Confidential Personnel)',
      secretKey: 'FILESERVER_HR_SECRET_SERVICE_KEY_2026'
    },
    'mailserver/corp': {
      serviceName: 'Corporate Secure Email Gateway',
      secretKey: 'MAILSERVER_SECRET_SERVICE_KEY_2026'
    }
  },
  // KDC User Database: Stores user master key derived from password using PBKDF2
  users: {
    'alice': {
      realm: 'CORP.ENTERPRISE.LOCAL',
      password: 'AliceStrongPassword2026!',
      // Derived master key Kc = PBKDF2(password, salt, 100000, 32, 'sha256')
      clientKey: crypto.pbkdf2Sync('AliceStrongPassword2026!', 'alice_salt_123', 100000, 32, 'sha256').toString('hex')
    }
  }
};

// Replay Cache on Application Server (records [client, timestamp, authenticatorHash] within skew window)
const serverReplayCache = new Map();
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // 5 minutes standard Kerberos clock skew

class KerberosKDC {
  constructor() {
    this.logs = [];
  }

  log(event, details) {
    this.logs.push({
      timestamp: new Date().toISOString(),
      event,
      details
    });
  }

  /**
   * STEP 1: Authentication Server (AS) Exchange
   * AS-REQ: Client requests Ticket Granting Ticket (TGT)
   */
  processASReq(clientId, serviceRequested = 'krbtgt/CORP.ENTERPRISE.LOCAL') {
    const user = KDC_SECRETS.users[clientId.toLowerCase()];
    if (!user) {
      throw new Error(`KDC_ERR_C_PRINCIPAL_UNKNOWN: Client '${clientId}' not found in KDC database`);
    }

    // Generate random session key between Client and TGS (Kc,tgs)
    const sessionKey_C_TGS = crypto.randomBytes(32).toString('hex');
    const issueTime = Date.now();
    const lifetimeMs = 8 * 3600 * 1000; // 8 hours TGT validity

    // 1. Build Ticket Granting Ticket (TGT) encrypted with TGS's Secret Key (Ktgs)
    const tgtPayload = {
      client: clientId,
      realm: user.realm,
      sessionKey_C_TGS: sessionKey_C_TGS,
      issueTimestamp: issueTime,
      expiryTimestamp: issueTime + lifetimeMs,
      flags: ['FORWARDABLE', 'PROXIABLE', 'RENEWABLE', 'INITIAL']
    };
    const encryptedTGT = encryptAES(KDC_SECRETS.tgsKey, tgtPayload);

    // 2. Build AS-REP encrypted with Client's Master Key (Kc)
    const asRepPayload = {
      sessionKey_C_TGS: sessionKey_C_TGS,
      serviceId: serviceRequested,
      tgtIssueTime: issueTime,
      tgtExpiryTime: issueTime + lifetimeMs,
      tgt: encryptedTGT
    };
    const encryptedASRep = encryptAES(user.clientKey, asRepPayload);

    this.log('AS-REP Issued', {
      client: clientId,
      ticketType: 'TGT',
      expiry: new Date(issueTime + lifetimeMs).toISOString()
    });

    return {
      asRepEncrypted: encryptedASRep,
      // For visual educational inspection:
      debugInfo: {
        clientKeyUsed: user.clientKey.substring(0, 16) + '...',
        sessionKey_C_TGS: sessionKey_C_TGS,
        tgtPlaintext: tgtPayload,
        tgtEncryptedEnvelope: encryptedTGT
      }
    };
  }

  /**
   * STEP 2: Ticket Granting Server (TGS) Exchange
   * TGS-REQ: Client presents TGT + Authenticator to request a Service Ticket (ST)
   */
  processTGSReq(encryptedTGT, encryptedAuthenticator, requestedServiceId) {
    // 1. TGS decrypts TGT using TGS Secret Key (Ktgs)
    let tgt;
    try {
      tgt = decryptAES(KDC_SECRETS.tgsKey, encryptedTGT);
    } catch (err) {
      throw new Error('KRB_AP_ERR_BAD_INTEGRITY: TGT decryption failed. Invalid or forged ticket.');
    }

    // Verify TGT expiration
    if (Date.now() > tgt.expiryTimestamp) {
      throw new Error('KRB_AP_ERR_TKT_EXPIRED: Ticket Granting Ticket has expired.');
    }

    // 2. TGS decrypts Authenticator using Session Key (Kc,tgs) extracted from TGT
    let authenticator;
    try {
      authenticator = decryptAES(tgt.sessionKey_C_TGS, encryptedAuthenticator);
    } catch (err) {
      throw new Error('KRB_AP_ERR_BAD_INTEGRITY: Authenticator decryption failed with session key.');
    }

    // Verify Authenticator matches TGT Client and check Clock Skew
    if (authenticator.client !== tgt.client) {
      throw new Error('KRB_AP_ERR_BADMATCH: Authenticator identity does not match ticket client.');
    }

    const clockDiff = Math.abs(Date.now() - authenticator.timestamp);
    if (clockDiff > MAX_CLOCK_SKEW_MS) {
      throw new Error(`KRB_AP_ERR_SKEW: Clock skew too great (${Math.round(clockDiff / 1000)}s > 300s limit).`);
    }

    // Check if target service exists
    const serviceInfo = KDC_SECRETS.services[requestedServiceId];
    if (!serviceInfo) {
      throw new Error(`KDC_ERR_S_PRINCIPAL_UNKNOWN: Service '${requestedServiceId}' not registered with KDC.`);
    }

    // 3. Generate Service Session Key (Kc,service)
    const sessionKey_C_Service = crypto.randomBytes(32).toString('hex');
    const issueTime = Date.now();
    const serviceLifetimeMs = 2 * 3600 * 1000; // 2 hours

    // 4. Build Service Ticket (ST) encrypted with Service Secret Key (Kv)
    const serviceTicketPayload = {
      client: tgt.client,
      realm: tgt.realm,
      service: requestedServiceId,
      sessionKey_C_Service: sessionKey_C_Service,
      issueTimestamp: issueTime,
      expiryTimestamp: issueTime + serviceLifetimeMs
    };
    const encryptedServiceTicket = encryptAES(serviceInfo.secretKey, serviceTicketPayload);

    // 5. Build TGS-REP encrypted with Kc,tgs
    const tgsRepPayload = {
      sessionKey_C_Service: sessionKey_C_Service,
      serviceId: requestedServiceId,
      ticketExpiry: issueTime + serviceLifetimeMs,
      serviceTicket: encryptedServiceTicket
    };
    const encryptedTGSRep = encryptAES(tgt.sessionKey_C_TGS, tgsRepPayload);

    this.log('TGS-REP Issued', {
      client: tgt.client,
      service: requestedServiceId,
      ticketType: 'ServiceTicket'
    });

    return {
      tgsRepEncrypted: encryptedTGSRep,
      debugInfo: {
        tgtDecrypted: tgt,
        authenticatorDecrypted: authenticator,
        sessionKey_C_Service: sessionKey_C_Service,
        serviceTicketPlaintext: serviceTicketPayload,
        serviceTicketEncrypted: encryptedServiceTicket
      }
    };
  }

  /**
   * STEP 3: Application Server Exchange (AP-REQ & AP-REP)
   * Client presents Service Ticket (ST) and Server Authenticator to Application Server.
   * Server validates ST, verifies Authenticator, checks Replay Cache, and sends AP-REP for MUTUAL AUTHENTICATION.
   */
  processAPReq(encryptedServiceTicket, encryptedAuthenticator, requestedServiceId) {
    const serviceInfo = KDC_SECRETS.services[requestedServiceId];
    if (!serviceInfo) {
      throw new Error(`Service '${requestedServiceId}' not configured.`);
    }

    // 1. Server decrypts Service Ticket using its private Service Key (Kv)
    let serviceTicket;
    try {
      serviceTicket = decryptAES(serviceInfo.secretKey, encryptedServiceTicket);
    } catch (err) {
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_BAD_INTEGRITY',
        message: 'Decryption of Service Ticket failed. Tampered or wrong service key.'
      };
    }

    // Check expiration
    if (Date.now() > serviceTicket.expiryTimestamp) {
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_TKT_EXPIRED',
        message: 'Service Ticket has expired.'
      };
    }

    // 2. Server decrypts Authenticator using Service Session Key (Kc,service)
    let authenticator;
    try {
      authenticator = decryptAES(serviceTicket.sessionKey_C_Service, encryptedAuthenticator);
    } catch (err) {
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_BAD_INTEGRITY',
        message: 'Decryption of Authenticator failed with service session key.'
      };
    }

    // Check client identity match
    if (authenticator.client !== serviceTicket.client) {
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_BADMATCH',
        message: 'Ticket client and Authenticator client mismatch.'
      };
    }

    // Check Clock Skew
    const clockDiff = Math.abs(Date.now() - authenticator.timestamp);
    if (clockDiff > MAX_CLOCK_SKEW_MS) {
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_SKEW',
        message: `Clock skew ${Math.round(clockDiff / 1000)}s exceeds tolerance window.`
      };
    }

    // 3. REPLAY CACHE DEFENSE CHECK:
    // Create unique signature of the authenticator (Client + Timestamp)
    const replayKey = `${authenticator.client}_${authenticator.timestamp}_${authenticator.nonce || ''}`;
    if (serverReplayCache.has(replayKey)) {
      const originalSeenTime = serverReplayCache.get(replayKey);
      return {
        success: false,
        errorCode: 'KRB_AP_ERR_REPEAT',
        replayAttackDetected: true,
        message: 'REPLAY ATTACK THWARTED: Request with identical Authenticator timestamp was already processed and logged in the Server Replay Cache!',
        details: {
          client: authenticator.client,
          timestamp: authenticator.timestamp,
          originalReceivedTime: originalSeenTime,
          replayReceivedTime: new Date().toISOString(),
          status: 'BLOCKED BY KERBEROS REPLAY CACHE ENGINE'
        }
      };
    }

    // Record in replay cache
    serverReplayCache.set(replayKey, new Date().toISOString());

    // Clean up replay cache entries older than skew window
    const now = Date.now();
    for (const [key, seenTime] of serverReplayCache.entries()) {
      if (now - new Date(seenTime).getTime() > MAX_CLOCK_SKEW_MS * 2) {
        serverReplayCache.delete(key);
      }
    }

    // 4. Server generates AP-REP for MUTUAL AUTHENTICATION
    // Server encrypts (Authenticator.timestamp + 1) using Kc,service
    const mutualAuthPayload = {
      serverTimestampConfirmation: authenticator.timestamp + 1,
      serviceName: serviceInfo.serviceName,
      status: 'MUTUAL_AUTHENTICATION_ESTABLISHED'
    };
    const encryptedAPRep = encryptAES(serviceTicket.sessionKey_C_Service, mutualAuthPayload);

    return {
      success: true,
      mutualAuthenticationVerified: true,
      serviceTicket: serviceTicket,
      authenticator: authenticator,
      apRepEncrypted: encryptedAPRep,
      grantedResource: {
        service: serviceInfo.serviceName,
        grantedTo: serviceTicket.client,
        accessGrantedAt: new Date().toISOString(),
        confidentialData: 'TOP_SECRET_CORP_PAYROLL_2026: Alice authorized for executive view.'
      }
    };
  }
}

module.exports = {
  KDC_SECRETS,
  serverReplayCache,
  KerberosKDC,
  encryptAES,
  decryptAES
};

