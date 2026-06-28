// DELIBERATELY VULNERABLE — test fixture for SAST scanner demo
// All credentials in this file are fake and for testing purposes only

const crypto = require('crypto');
const { Client } = require('pg');

// 1. Defect Test Node: Hardcoded Secrets
const jwt_secret = "super_secret_signing_key_abc123_dont_share";
const apiKey = 'AIzaSyA1_unprotected_cloud_key';

// 2. Defect Test Node: Vulnerable SQL Construction
async function getUserProfile(userInputId) {
    const client = new Client();
    // Vulnerable string interpolation:
    const query = `SELECT * FROM users WHERE id = ${userInputId}`;
    return await client.query(query);
}

// 3. Defect Test Node: Dynamic Evaluation Injection
function processExpression(inputString) {
    // Dangerous execution behavior:
    return eval(inputString);
}

// 4. Defect Test Node: Legacy / Broken Cryptography
function hashPasswordOldWay(password) {
    // Insecure algorithm choice:
    return crypto.createHash('md5').update(password).digest('hex');
}

console.log("Mock system running nominal operations parameters.");