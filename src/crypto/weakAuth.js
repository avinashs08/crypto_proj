// src/crypto/weakAuth.js
// Demonstration of Weak Authentication Schemes and their inherent vulnerabilities
const crypto = require('crypto');

// Simulated vulnerable user database (stores weak unsalted MD5 hashes)
const WEAK_USER_DB = {
  'alice': {
    username: 'alice',
    plaintextPassword: 'password123',
    // MD5 unsalted hash of 'password123' -> 482c811da5d5b4bc6d497ffa98491e38
    passwordHashMD5: crypto.createHash('md5').update('password123').digest('hex'),
    role: 'HR_Analyst',
    balance: 50000
  },
  'bob': {
    username: 'bob',
    plaintextPassword: 'admin2024',
    // MD5 unsalted hash of 'admin2024' -> 5ebe2294ecd0e0f08eab7690d2a6ee69 (or similar)
    passwordHashMD5: crypto.createHash('md5').update('admin2024').digest('hex'),
    role: 'System_Admin',
    balance: 100000
  },
  'charlie': {
    username: 'charlie',
    plaintextPassword: 'crypto101',
    passwordHashMD5: crypto.createHash('md5').update('crypto101').digest('hex'),
    role: 'Research_Engineer',
    balance: 75000
  }
};

// In-memory active tokens issued by the weak server (static/stateless, no timestamp/nonce)
const activeWeakTokens = new Map();

/**
 * Weak Login Type 1: Plaintext / HTTP Basic Auth simulation
 * Credentials sent unencrypted or in base64 across the wire
 */
function weakLoginPlaintext(username, password) {
  const user = WEAK_USER_DB[username.toLowerCase()];
  if (!user || user.plaintextPassword !== password) {
    return {
      success: false,
      error: 'Invalid credentials',
      packetTrace: {
        method: 'POST',
        endpoint: '/auth/basic',
        headers: {
          'Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        payload: { username, password }
      }
    };
  }

  // Issue a weak static token (MD5 of username + fixed secret, no expiry, no nonce)
  const weakToken = crypto.createHash('md5').update(username + '_STATIC_SECRET_KEY').digest('hex');
  activeWeakTokens.set(weakToken, { username: user.username, role: user.role, issuedAt: new Date().toISOString() });

  return {
    success: true,
    token: weakToken,
    user: { username: user.username, role: user.role, balance: user.balance },
    packetTrace: {
      method: 'POST',
      endpoint: '/auth/basic',
      headers: {
        'Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
        'Content-Type': 'application/json'
      },
      payload: { username, password },
      wireData: `POST /auth/basic HTTP/1.1\r\nHost: insecure-server.corp\r\nAuthorization: Basic ${Buffer.from(`${username}:${password}`).toString('base64')}\r\n\r\n{"username":"${username}","password":"${password}"}`
    }
  };
}

/**
 * Weak Server Resource Access: Validates weak static token
 * VULNERABILITY: No timestamp validation, no nonce, no client IP/fingerprint binding.
 * Accepts ANY captured token regardless of who presents it or how many times it was used.
 */
function accessWeakResource(token, action = 'view_balance') {
  if (!token || !activeWeakTokens.has(token)) {
    return {
      success: false,
      statusCode: 401,
      error: 'Unauthorized: Invalid or missing token'
    };
  }

  const session = activeWeakTokens.get(token);
  const user = WEAK_USER_DB[session.username];

  return {
    success: true,
    statusCode: 200,
    message: `Resource granted for ${session.username} (${session.role})`,
    data: {
      user: session.username,
      role: session.role,
      balance: user ? user.balance : 0,
      timestamp: new Date().toISOString(),
      actionExecuted: action
    }
  };
}

module.exports = {
  WEAK_USER_DB,
  activeWeakTokens,
  weakLoginPlaintext,
  accessWeakResource
};

