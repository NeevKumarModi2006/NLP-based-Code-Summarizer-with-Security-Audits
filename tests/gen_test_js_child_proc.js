const { exec } = require('child_process');
function ping(host) {
    // VULNERABLE: Command Injection
    exec('ping ' + host, (err, stdout, stderr) => {
        if (err) return;
        console.log(stdout);
    });
}