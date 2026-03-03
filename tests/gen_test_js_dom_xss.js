var search = location.search.substring(1);
// VULNERABLE: DOM XSS
document.body.innerHTML = search;