function getSecret() {
    // VULNERABLE: Hardcoded Secret
    const jwt_secret = "my_super_secure_secret_key_123";
    return jwt_secret;
}