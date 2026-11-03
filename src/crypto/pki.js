// src/crypto/pki.js
// Public Key Infrastructure (PKI), X.509-compliant Digital Certificates & Mutual TLS (mTLS) Engine
const crypto = require('crypto');

/**
 * Generate 2048-bit RSA Key Pair
 */
function generateRSAKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
}

/**
 * Certificate Authority and PKI Management Engine
 */
class PKIEngine {
  constructor() {
    this.rootCA = null;
    this.issuedCertificates = new Map();
    this.certificateRevocationList = new Set(); // CRL containing revoked serial numbers
    this.initRootCA();
  }

  /**
   * Initialize Self-Signed Root Certificate Authority (Root CA)
   */
  initRootCA() {
    const keyPair = generateRSAKeyPair();
    const serialNumber = 'CA-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const issueDate = new Date();
    const expiryDate = new Date(issueDate.getTime() + 10 * 365 * 24 * 3600 * 1000); // 10 years

    const caTbsCertificate = {
      serialNumber,
      issuer: 'CN=Global Enterprise Root CA, O=SecureTrust Corp, C=US',
      subject: 'CN=Global Enterprise Root CA, O=SecureTrust Corp, C=US',
      validity: {
        notBefore: issueDate.toISOString(),
        notAfter: expiryDate.toISOString()
      },
      publicKeyPEM: keyPair.publicKey,
      keyUsage: ['Digital Signature', 'Certificate Signing', 'CRL Signing', 'Key Encipherment'],
      isCA: true
    };

    // Self-sign the root certificate using its own private key
    const signer = crypto.createSign('SHA256');
    signer.update(JSON.stringify(caTbsCertificate));
    signer.end();
    const signature = signer.sign(keyPair.privateKey, 'hex');

    this.rootCA = {
      certificate: {
        ...caTbsCertificate,
        signatureAlgorithm: 'sha256WithRSAEncryption',
        signatureValue: signature
      },
      publicKeyPEM: keyPair.publicKey,
      privateKeyPEM: keyPair.privateKey
    };

    this.issuedCertificates.set(serialNumber, this.rootCA.certificate);
    return this.rootCA.certificate;
  }

  /**
   * Create Certificate Signing Request (CSR)
   */
  createCSR(subjectDN, keyPair) {
    const csrBody = {
      subject: subjectDN,
      publicKeyPEM: keyPair.publicKey,
      timestamp: new Date().toISOString()
    };

    // Applicant signs CSR with its private key (Proof of Possession)
    const signer = crypto.createSign('SHA256');
    signer.update(JSON.stringify(csrBody));
    signer.end();
    const signature = signer.sign(keyPair.privateKey, 'hex');

    return {
      csrBody,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      applicantSignature: signature
    };
  }

  /**
   * Root CA signs CSR and issues X.509-style Digital Certificate
   */
  issueCertificate(csr, keyUsage = ['Digital Signature', 'Key Encipherment'], validityDays = 365) {
    // 1. Verify CSR Signature using Applicant's Public Key
    const verifier = crypto.createVerify('SHA256');
    verifier.update(JSON.stringify(csr.csrBody));
    verifier.end();
    const isValidCSR = verifier.verify(csr.csrBody.publicKeyPEM, csr.applicantSignature, 'hex');

    if (!isValidCSR) {
      throw new Error('CSR_VERIFICATION_FAILED: Applicant signature over CSR is invalid!');
    }

    // 2. Issue Certificate Body
    const serialNumber = 'CERT-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const notBefore = new Date();
    const notAfter = new Date(notBefore.getTime() + validityDays * 24 * 3600 * 1000);

    const tbsCert = {
      serialNumber,
      version: 3,
      issuer: this.rootCA.certificate.subject,
      subject: csr.csrBody.subject,
      validity: {
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString()
      },
      publicKeyPEM: csr.csrBody.publicKeyPEM,
      keyUsage: keyUsage,
      isCA: false
    };

    // 3. CA signs Certificate using Root CA Private Key
    const signer = crypto.createSign('SHA256');
    signer.update(JSON.stringify(tbsCert));
    signer.end();
    const caSignature = signer.sign(this.rootCA.privateKeyPEM, 'hex');

    const certificate = {
      ...tbsCert,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      caSignatureValue: caSignature,
      issuerSerialNumber: this.rootCA.certificate.serialNumber
    };

    this.issuedCertificates.set(serialNumber, certificate);
    return certificate;
  }

  /**
   * Validate a Digital Certificate against Root CA & CRL
   */
  verifyCertificate(certificate) {
    // 1. Check Revocation
    if (this.certificateRevocationList.has(certificate.serialNumber)) {
      return {
        valid: false,
        error: `CERTIFICATE_REVOKED: Certificate ${certificate.serialNumber} is listed on the Certificate Revocation List (CRL)!`,
        reason: 'Revoked by Certificate Authority (Key compromise or administrative revocation)'
      };
    }

    // 2. Check Validity Period
    const now = new Date();
    if (now < new Date(certificate.validity.notBefore) || now > new Date(certificate.validity.notAfter)) {
      return {
        valid: false,
        error: `CERTIFICATE_EXPIRED: Current time outside validity window (${certificate.validity.notBefore} to ${certificate.validity.notAfter})`
      };
    }

    // 3. Verify Cryptographic Signature against Root CA Public Key
    const tbsCopy = {
      serialNumber: certificate.serialNumber,
      version: certificate.version,
      issuer: certificate.issuer,
      subject: certificate.subject,
      validity: certificate.validity,
      publicKeyPEM: certificate.publicKeyPEM,
      keyUsage: certificate.keyUsage,
      isCA: certificate.isCA
    };

    const verifier = crypto.createVerify('SHA256');
    verifier.update(JSON.stringify(tbsCopy));
    verifier.end();

    const isSignatureValid = verifier.verify(this.rootCA.publicKeyPEM, certificate.caSignatureValue, 'hex');
    if (!isSignatureValid) {
      return {
        valid: false,
        error: 'SIGNATURE_INVALID: Digital certificate signature does NOT match Trusted Root CA key!'
      };
    }

    return {
      valid: true,
      verifiedBy: this.rootCA.certificate.subject,
      subject: certificate.subject,
      serialNumber: certificate.serialNumber
    };
  }

  /**
   * Revoke a Certificate (adds to CRL)
   */
  revokeCertificate(serialNumber, reason = 'Key Compromise / Administrative Revocation') {
    if (!this.issuedCertificates.has(serialNumber)) {
      throw new Error(`Certificate with serial number ${serialNumber} not found.`);
    }
    this.certificateRevocationList.add(serialNumber);
    return {
      success: true,
      revokedSerialNumber: serialNumber,
      crlSize: this.certificateRevocationList.size,
      reason,
      revocationTimestamp: new Date().toISOString()
    };
  }

  /**
   * Full Mutual TLS (mTLS) Handshake Simulation
   * Both client and server authenticate each other using X.509 certificates and RSA signatures.
   */
  simulateMTLSHandshake(clientKeyPair, clientCert, serverKeyPair, serverCert) {
    const transcript = [];

    // STEP 1: ClientHello
    const clientRandom = crypto.randomBytes(32).toString('hex');
    transcript.push({
      step: '1. ClientHello',
      sender: 'Client',
      receiver: 'Server',
      content: {
        protocolVersion: 'TLS 1.3 / mTLS',
        clientRandom,
        supportedCipherSuites: [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_RSA_WITH_AES_256_GCM_SHA384'
        ],
        extensions: ['server_name', 'supported_groups', 'signature_algorithms']
      }
    });

    // STEP 2: ServerHello & Server Certificate & CertificateRequest
    const serverRandom = crypto.randomBytes(32).toString('hex');
    const selectedCipher = 'TLS_AES_256_GCM_SHA384';
    transcript.push({
      step: '2. ServerHello & Server Certificate',
      sender: 'Server',
      receiver: 'Client',
      content: {
        serverRandom,
        selectedCipherSuite: selectedCipher,
        serverCertificate: {
          serialNumber: serverCert.serialNumber,
          subject: serverCert.subject,
          issuer: serverCert.issuer,
          signatureAlgorithm: serverCert.signatureAlgorithm
        },
        certificateRequest: {
          message: 'mTLS Enabled: Requesting Client Certificate for mutual authentication',
          acceptedCAs: [this.rootCA.certificate.subject]
        }
      }
    });

    // STEP 3: Client validates Server Certificate
    const serverCertCheck = this.verifyCertificate(serverCert);
    if (!serverCertCheck.valid) {
      return {
        handshakeSuccess: false,
        failedAtStep: 'Client Server-Certificate Validation',
        error: serverCertCheck.error,
        transcript
      };
    }
    transcript.push({
      step: '3. Client Certificate Verification (Server Auth)',
      sender: 'Client (Internal)',
      receiver: 'Client',
      content: {
        serverCertificateValid: true,
        trustedRootCA: this.rootCA.certificate.subject,
        validationChecks: ['Signature verified with CA Public Key', 'Expiration check passed', 'CRL check passed']
      }
    });

    // STEP 4: Client sends Client Certificate & PreMasterSecret encrypted with Server Public Key
    // Also sends CertificateVerify: Digital signature over handshake transcript using Client Private Key!
    const preMasterSecret = crypto.randomBytes(48); // 48-byte TLS PreMasterSecret
    
    // Encrypt PreMasterSecret with Server's RSA Public Key
    const encryptedPreMasterSecret = crypto.publicEncrypt(
      { key: serverKeyPair.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      preMasterSecret
    ).toString('hex');

    // Create CertificateVerify signature
    const handshakeHash = crypto.createHash('sha256').update(clientRandom + serverRandom).digest();
    const certVerifySigner = crypto.createSign('SHA256');
    certVerifySigner.update(handshakeHash);
    certVerifySigner.end();
    const clientCertVerifySignature = certVerifySigner.sign(clientKeyPair.privateKey, 'hex');

    transcript.push({
      step: '4. Client Certificate & Key Exchange',
      sender: 'Client',
      receiver: 'Server',
      content: {
        clientCertificate: {
          serialNumber: clientCert.serialNumber,
          subject: clientCert.subject,
          issuer: clientCert.issuer
        },
        encryptedPreMasterSecret: encryptedPreMasterSecret.substring(0, 64) + '... [Encrypted with Server RSA Public Key]',
        certificateVerifySignature: clientCertVerifySignature.substring(0, 64) + '... [Signed with Client RSA Private Key]'
      }
    });

    // STEP 5: Server validates Client Certificate and Client Signature (mTLS Mutual Auth)
    const clientCertCheck = this.verifyCertificate(clientCert);
    if (!clientCertCheck.valid) {
      return {
        handshakeSuccess: false,
        failedAtStep: 'Server Client-Certificate Validation (mTLS)',
        error: clientCertCheck.error,
        transcript
      };
    }

    // Server verifies Client's CertificateVerify signature using Client Public Key
    const certVerifyCheck = crypto.createVerify('SHA256');
    certVerifyCheck.update(handshakeHash);
    certVerifyCheck.end();
    const isClientOwnerVerified = certVerifyCheck.verify(clientCert.publicKeyPEM, clientCertVerifySignature, 'hex');

    if (!isClientOwnerVerified) {
      return {
        handshakeSuccess: false,
        failedAtStep: 'Server Client Ownership Verification',
        error: 'Client failed to prove possession of private key corresponding to client certificate!',
        transcript
      };
    }

    // Server decrypts PreMasterSecret using Server's RSA Private Key
    const decryptedPreMasterSecret = crypto.privateDecrypt(
      { key: serverKeyPair.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(encryptedPreMasterSecret, 'hex')
    );

    // STEP 6: Key Derivation (PRF) - Both compute Master Secret & Session Keys
    // MasterKey = HMAC-SHA256(PreMasterSecret, "master secret" + clientRandom + serverRandom)
    const masterSecret = crypto.createHmac('sha256', decryptedPreMasterSecret)
      .update('master secret' + clientRandom + serverRandom)
      .digest();

    const symmetricSessionKey = crypto.createHmac('sha256', masterSecret)
      .update('key expansion' + clientRandom + serverRandom)
      .digest('hex');

    transcript.push({
      step: '5. Server Client Verification & Key Derivation',
      sender: 'Server (Internal)',
      receiver: 'Server',
      content: {
        clientCertificateValid: true,
        proofOfPossessionVerified: true,
        preMasterSecretDecrypted: true,
        masterSecretDerived: true,
        symmetricSessionKey: symmetricSessionKey.substring(0, 32) + '... [AES-256 Key Derived]'
      }
    });

    // STEP 7: Finished / Encrypted Application Tunnel
    const samplePayload = {
      message: 'Confidential ERP Database Query: Employee #10492 Security Clearance Granted.',
      confidentiality: 'End-to-End AES-256-GCM Encrypted via mTLS Session',
      authenticatedSubject: clientCert.subject
    };

    // Encrypt sample application data with symmetric session key
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(symmetricSessionKey, 'hex'), iv);
    let appDataCipher = cipher.update(JSON.stringify(samplePayload), 'utf8', 'hex');
    appDataCipher += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    transcript.push({
      step: '6. Finished & Encrypted Application Tunnel Active',
      sender: 'Bidirectional (Client <-> Server)',
      receiver: 'Secure Tunnel',
      content: {
        status: 'MUTUAL TLS 1.3 CONNECTION ESTABLISHED',
        cipherSuite: 'TLS_AES_256_GCM_SHA384',
        mutualAuthentication: 'CONFIRMED (Both endpoints cryptographically authenticated by Root CA)',
        encryptedSampleTraffic: {
          iv: iv.toString('hex'),
          ciphertext: appDataCipher,
          authTag: authTag,
          decryptedVerification: samplePayload
        }
      }
    });

    return {
      handshakeSuccess: true,
      cipherSuite: selectedCipher,
      sessionKey: symmetricSessionKey,
      clientIdentity: clientCert.subject,
      serverIdentity: serverCert.subject,
      rootCA: this.rootCA.certificate.subject,
      transcript
    };
  }
}

module.exports = {
  PKIEngine,
  generateRSAKeyPair
};

