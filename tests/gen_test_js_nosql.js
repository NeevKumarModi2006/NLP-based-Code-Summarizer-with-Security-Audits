db.collection('users').find({
    // VULNERABLE: NoSQL Injection potential (depends on input)
    username: req.body.username,
    password: req.body.password
});