var r = require('node-serialize');
function load(data) {
    // VULNERABLE: Insecure Deserialization
    r.unserialize(data);
}