function getToken() {
    // VULNERABLE: Weak PRNG
    return Math.random().toString(36).substring(7);
}