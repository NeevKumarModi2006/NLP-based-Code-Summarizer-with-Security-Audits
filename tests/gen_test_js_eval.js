function calc(expr) {
    // VULNERABLE: Eval Injection
    return eval(expr);
}