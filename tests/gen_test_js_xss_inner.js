function showUser(name) {
    // VULNERABLE: XSS
    document.getElementById('user').innerHTML = "Hello " + name;
}