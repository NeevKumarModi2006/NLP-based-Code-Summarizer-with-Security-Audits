function writeData(data) {
    // VULNERABLE: XSS
    document.write(data);
}