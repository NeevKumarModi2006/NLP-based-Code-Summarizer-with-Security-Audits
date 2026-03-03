const { exec } = require('child_process');
const fs = require('fs');
const express = require('express');
const app = express();

class VulnerableHandler {
    constructor() {
        this.secrets = "super_secret_key";
    }

    handleRequest(req, res) {
        const userInput = req.query.input;

        // VULN: Eval Injection
        eval(userInput);

        // VULN: XSS
        res.send("<h1>" + userInput + "</h1>");
    }

    runSystemCommand(cmd) {
        // VULN: Command Injection
        exec(cmd, (err, stdout, stderr) => {
            console.log(stdout);
        });
    }

    mergeObjects(target, source) {
        for (let key in source) {
            // VULN: Prototype Pollution
            target[key] = source[key];
        }
    }
    
    getAdminToken() {
        // VULN: Hardcoded Secret
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    }
}

// VULN: DOM XSS pattern (frontend context simulated)
function updateDOM(data) {
    document.getElementById('content').innerHTML = data;
    document.write(data);
}