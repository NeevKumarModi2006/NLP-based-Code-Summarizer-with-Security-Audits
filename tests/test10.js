
const express = require('express');
const app = express();

app.get('/', (req, res) => {
    const userParam = req.query.name;
    
    // VULNERABLE: Reflected XSS
    res.send(`<h1>Hello ${userParam}</h1>`); 

    // VULNERABLE: DOM XSS
    // document.write(userParam); // (Contextually dangerous if client-side)
});

function merge(target, source) {
    for (let key in source) {
        // VULNERABLE: Prototype Pollution
        if (key === "__proto__" || key === "constructor") {
            // Dangerous merge
        }
        target[key] = source[key];
    }
}

app.listen(3000);
