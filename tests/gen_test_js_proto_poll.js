function merge(target, source) {
    for (let key in source) {
        // VULNERABLE: Prototype Pollution
        target[key] = source[key];
    }
}