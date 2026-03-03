const fs = require('fs');
const crypto = require('crypto');

// Use of a weak/deprecated hash algorithm (MD5)
function getFileHash(filePath) {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('md5').update(content).digest('hex');
}

// Security issue: Logging potentially sensitive info (Path exposure)
console.log("Processing file at: " + __dirname + "/configs/settings.json");