import subprocess
import json
import logging
import math
import os
import sys
import re

class Scanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def scan_file(self, file_path: str):
        """
        Runs semgrep on a single file using the native binary.
        Falls back to internal Regex/AST scan if Semgrep fails or finds nothing.
        """
        try:
            # 1. SETUP ENVIRONMENT
            env = os.environ.copy()
            appdata_path = os.environ.get('APPDATA', '')
            user_scripts = os.path.join(appdata_path, 'Python', 'Python313', 'Scripts')
            if os.path.exists(user_scripts):
                env['PATH'] = user_scripts + os.pathsep + env.get('PATH', '')

            # 2. CONSTRUCT COMMAND
            script_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(script_dir, '..', 'rules.yaml')
            rules_path = os.path.normpath(rules_path)
            config = rules_path if os.path.exists(rules_path) else 'p/security-audit'

            cmd = f'semgrep scan --config "{config}" --json --quiet "{file_path}"'

            # 3. EXECUTE SCAN
            result = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True)

            findings = []
            risk_score = 0.0

            # 4. ROBUST JSON PARSING
            if result.stdout:
                try:
                    raw_output = result.stdout.strip()
                    start_idx = raw_output.find('{')
                    end_idx = raw_output.rfind('}') + 1
                    if start_idx != -1 and end_idx != -1:
                        json_str = raw_output[start_idx:end_idx]
                        json_output = json.loads(json_str)
                        findings = self._parse_semgrep_output(json_output)
                        risk_score = self._calculate_risk_score(findings, file_path)
                    else:
                        self.logger.warning("Semgrep executed but returned no valid JSON.")
                except json.JSONDecodeError:
                    self.logger.error("Failed to decode Semgrep JSON output.")

            # 5. FALLBACK LOGIC
            if not findings:
                self.logger.info("No Semgrep findings. Running internal fallback scanner...")
                return self._fallback_scan(file_path)

            return findings, risk_score

        except Exception as e:
            self.logger.error(f"Security scan failed: {str(e)}")
            return self._fallback_scan(file_path)

    def _parse_semgrep_output(self, json_output: dict):
        parsed_findings = []
        results = json_output.get('results', [])
        for item in results:
            finding = {
                'check_id': item.get('check_id'),
                'file': item.get('path'),
                'line': item.get('start', {}).get('line'),
                'message': item.get('extra', {}).get('message'),
                'severity': item.get('extra', {}).get('severity', 'INFO').upper(),
                'snippet': item.get('extra', {}).get('lines', '').strip()
            }
            parsed_findings.append(finding)
        return parsed_findings

    def _fallback_scan(self, file_path: str):
        """
        PURPOSE: Offline security scanner — a direct regex mirror of rules.yaml.

        When Semgrep is unavailable (not installed, network error, or returns no results),
        this method provides equivalent multi-category coverage using compiled regexes mapped
        1:1 to the rule IDs and categories defined in rules.yaml. It covers all 4 supported
        languages (Python, JavaScript, Java, C) across the following attack categories:

          - Injection        : SQL, Command, Code (eval/exec), SSTI, LDAP, NoSQL, ReDoS
          - Deserialization  : pickle, yaml, jsonpickle, dill, ObjectInputStream, XMLDecoder, XStream
          - Cryptography     : MD5, SHA-1, DES, AES-ECB, rand/random, predictable seeds
          - Secrets          : Hardcoded passwords, AWS keys, JWT secrets, API keys
          - Path Traversal   : open(), send_file, fs.readFile, new File(), Paths.get()
          - XSS              : innerHTML, outerHTML, document.write, dangerouslySetInnerHTML
          - SSRF             : requests.get, urllib, axios, fetch, URL.openConnection
          - Prototype Pollution : bracket-notation key assignment
          - Misconfiguration : CORS wildcard, insecure cookies, Flask debug=True, TLS bypass
          - Logging          : passwords in console/log output, logging.exception

        Each finding includes: rule_id, file, line number, CWE-tagged message, severity, and snippet.
        """
        findings = []
        try:
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {'.py': 'python', '.js': 'javascript', '.java': 'java', '.c': 'c'}
            language = lang_map.get(ext)
            if not language:
                return [], 0.0

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            lines = content.splitlines()

            shared_patterns = [
                (r'AKIA[0-9A-Z]{16}',
                 '[CWE-798] Hardcoded AWS Access Key ID detected. Revoke and rotate immediately.',
                 'ERROR', 'fallback.shared.aws-key'),
            ]

            python_patterns = [
                # SQL Injection
                (r'\.execute\s*\(\s*f["\']',
                 '[CWE-89] SQL Injection via f-string in execute(). Use parameterized queries.',
                 'ERROR', 'fallback.py.sqli-fstring'),
                (r'\.execute\s*\([^)]*["\'].*\s*%\s*',
                 '[CWE-89] SQL Injection via %-format in execute(). Use parameterized queries.',
                 'ERROR', 'fallback.py.sqli-format'),
                (r'\.execute\s*\(\s*\w[^"\'()\n]*\+',
                 '[CWE-89] SQL Injection via string concat in execute(). Use parameterized queries.',
                 'ERROR', 'fallback.py.sqli-concat'),
                (r'\.executemany\s*\(\s*\w[^"\'()\n]*\+',
                 '[CWE-89] SQL Injection in executemany() via string concat.',
                 'ERROR', 'fallback.py.sqli-executemany'),
                # Command Injection
                (r'subprocess\.Popen\b.*shell\s*=\s*True',
                 '[CWE-78] Command Injection: subprocess.Popen with shell=True.',
                 'ERROR', 'fallback.py.cmd-popen'),
                (r'subprocess\.call\b.*shell\s*=\s*True',
                 '[CWE-78] Command Injection: subprocess.call with shell=True.',
                 'ERROR', 'fallback.py.cmd-call'),
                (r'subprocess\.run\b.*shell\s*=\s*True',
                 '[CWE-78] Command Injection: subprocess.run with shell=True.',
                 'ERROR', 'fallback.py.cmd-run'),
                (r'\bos\.system\s*\(',
                 '[CWE-78] Command Injection via os.system(). Use subprocess with a list.',
                 'ERROR', 'fallback.py.cmd-os-system'),
                (r'\bos\.popen\s*\(',
                 '[CWE-78] Command Injection via os.popen(). Use subprocess module.',
                 'ERROR', 'fallback.py.cmd-os-popen'),
                # Code Injection
                (r'\beval\s*\(',
                 '[CWE-94] Code Injection via eval(). Never pass user-controlled data.',
                 'ERROR', 'fallback.py.code-eval'),
                (r'\bexec\s*\(',
                 '[CWE-94] Code Injection via exec(). Never pass user-controlled data.',
                 'ERROR', 'fallback.py.code-exec'),
                (r'\bcompile\s*\(\s*\w',
                 '[CWE-94] Code Injection risk: compile() with dynamic input.',
                 'WARNING', 'fallback.py.code-compile'),
                # SSTI
                (r'jinja2\.Template\s*\(\s*\w',
                 '[CWE-94] SSTI: Jinja2 template built from dynamic input. Never render user templates.',
                 'ERROR', 'fallback.py.ssti-jinja2'),
                # LDAP
                (r'\.search_s\s*\(',
                 '[CWE-90] Potential LDAP Injection. Sanitize all filter components.',
                 'WARNING', 'fallback.py.ldap-injection'),
                # XPath
                (r'\.xpath\s*\(\s*\w',
                 '[CWE-643] Potential XPath Injection. Use parameterized XPath queries.',
                 'WARNING', 'fallback.py.xpath-injection'),
                # Deserialization
                (r'\bpickle\.loads\s*\(',
                 '[CWE-502] Unsafe deserialization: pickle.loads() can execute arbitrary code.',
                 'ERROR', 'fallback.py.deser-pickle-loads'),
                (r'\bpickle\.load\s*\(',
                 '[CWE-502] Unsafe deserialization: pickle.load() can execute arbitrary code.',
                 'ERROR', 'fallback.py.deser-pickle-load'),
                (r'\bcPickle\.loads\s*\(',
                 '[CWE-502] Unsafe deserialization via cPickle.loads().',
                 'ERROR', 'fallback.py.deser-cpickle'),
                (r'\byaml\.load\s*\(',
                 '[CWE-502] Unsafe YAML deserialization. Use yaml.safe_load() instead.',
                 'ERROR', 'fallback.py.deser-yaml-load'),
                (r'\bjsonpickle\.decode\s*\(',
                 '[CWE-502] Unsafe deserialization via jsonpickle.decode(). Only decode trusted data.',
                 'ERROR', 'fallback.py.deser-jsonpickle'),
                (r'\bdill\.loads\s*\(',
                 '[CWE-502] Unsafe deserialization via dill.loads(). Avoid on untrusted data.',
                 'ERROR', 'fallback.py.deser-dill'),
                (r'\bshelve\.open\s*\(',
                 '[CWE-502] shelve uses pickle internally. Ensure shelf file is not user-supplied.',
                 'WARNING', 'fallback.py.deser-shelve'),
                (r'\bmarshal\.loads\s*\(',
                 '[CWE-502] Unsafe deserialization: marshal.loads() on untrusted data.',
                 'WARNING', 'fallback.py.deser-marshal'),
                # Cryptography
                (r'\bhashlib\.md5\s*\(',
                 '[CWE-327] Weak hash MD5. Use hashlib.sha256() or stronger.',
                 'WARNING', 'fallback.py.crypto-md5'),
                (r'\bhashlib\.sha1\s*\(',
                 '[CWE-327] Weak hash SHA-1. Use SHA-256 or stronger.',
                 'WARNING', 'fallback.py.crypto-sha1'),
                (r'\bARC4\.new\s*\(',
                 '[CWE-327] RC4 cipher is broken and must not be used.',
                 'ERROR', 'fallback.py.crypto-rc4'),
                (r'\bCipher\.DES\.new\s*\(',
                 '[CWE-327] Weak cipher DES detected. Use AES-256-GCM.',
                 'ERROR', 'fallback.py.crypto-des'),
                (r'ssl\._create_unverified_context\s*\(',
                 '[CWE-295] SSL certificate verification disabled. Allows MITM attacks.',
                 'ERROR', 'fallback.py.crypto-ssl-noverify'),
                (r'requests\.\w+\s*\(.*verify\s*=\s*False',
                 '[CWE-295] SSL verification disabled in requests. Set verify=True.',
                 'ERROR', 'fallback.py.crypto-requests-noverify'),
                (r'\brandom\.random\s*\(',
                 '[CWE-338] Non-cryptographic PRNG. Use secrets module for security-sensitive values.',
                 'WARNING', 'fallback.py.crypto-prng-random'),
                (r'\brandom\.randint\s*\(',
                 '[CWE-338] Non-cryptographic PRNG (randint). Use secrets.randbelow() for tokens.',
                 'WARNING', 'fallback.py.crypto-prng-randint'),
                # Secrets
                (r'\bpassword\s*=\s*["\'][^"\']{1,}["\']',
                 '[CWE-259] Hardcoded password detected. Use environment variables.',
                 'ERROR', 'fallback.py.secrets-password'),
                (r'\bSECRET_KEY\s*=\s*["\'][^"\']{1,}["\']',
                 '[CWE-321] Hardcoded SECRET_KEY. Rotate immediately and use env vars.',
                 'ERROR', 'fallback.py.secrets-secret-key'),
                # Path Traversal
                (r'\bsend_file\s*\(\s*\w',
                 '[CWE-22] Path Traversal in Flask send_file(). Use safe_join().',
                 'ERROR', 'fallback.py.path-send-file'),
                (r'\bos\.path\.join\s*\(\s*\w[^,)]+,\s*\w',
                 '[CWE-22] os.path.join with user-controlled input can escape base directory.',
                 'WARNING', 'fallback.py.path-os-path-join'),
                # XXE (Python XML)
                (r'xml\.etree\.ElementTree\.parse\s*\(',
                 '[CWE-611] XXE: ElementTree.parse is not safe against XXE by default.',
                 'WARNING', 'fallback.py.xxe-etree'),
                (r'lxml\.etree\.parse\s*\(',
                 '[CWE-611] XXE: lxml.etree.parse without a safe XMLParser.',
                 'ERROR', 'fallback.py.xxe-lxml'),
                # SSRF
                (r'requests\.get\s*\(\s*\w',
                 '[CWE-918] Potential SSRF: requests.get() with dynamic URL. Validate and allowlist.',
                 'WARNING', 'fallback.py.ssrf-requests'),
                (r'urllib\.request\.urlopen\s*\(\s*\w',
                 '[CWE-918] Potential SSRF via urllib.request.urlopen(). Validate the URL.',
                 'WARNING', 'fallback.py.ssrf-urllib'),
                # Misconfiguration
                (r'app\.run\s*\(.*debug\s*=\s*True',
                 '[CWE-94] Flask debug=True enables remote code execution. Never use in production.',
                 'ERROR', 'fallback.py.misc-flask-debug'),
                (r'@csrf_exempt',
                 '[CWE-352] CSRF protection disabled via @csrf_exempt.',
                 'WARNING', 'fallback.py.csrf-exempt'),
                (r'\bredirect\s*\(\s*\w',
                 '[CWE-601] Open Redirect: redirect() with dynamic URL. Validate destination.',
                 'WARNING', 'fallback.py.open-redirect'),
                # ORM raw SQL
                (r'\.objects\.raw\s*\(\s*\w[^"\'()\n]*\+',
                 '[CWE-89] SQL Injection via Django raw() with string concatenation.',
                 'ERROR', 'fallback.py.django-raw-sqli'),
                # Logging
                (r'\blogging\.exception\s*\(',
                 '[CWE-209] Logging full exception may expose stack traces. Redact sensitive fields.',
                 'INFO', 'fallback.py.logging-exception'),
                (r'\bprint\s*\(\s*\w',
                 '[CWE-532] Potential sensitive data written to stdout via print(). Use structured logging.',
                 'INFO', 'fallback.py.print-sensitive'),
            ]

            js_patterns = [
                # Code Injection
                (r'\beval\s*\(',
                 '[CWE-94] Code Injection via eval(). Never pass user data to eval().',
                 'ERROR', 'fallback.js.code-eval'),
                (r'\bnew\s+Function\s*\(',
                 '[CWE-94] Code Injection: new Function() with dynamic input is equivalent to eval().',
                 'ERROR', 'fallback.js.code-function-ctor'),
                (r'setTimeout\s*\(\s*["\']',
                 '[CWE-94] Code Injection: setTimeout() with string arg evaluates it as code.',
                 'ERROR', 'fallback.js.code-settimeout'),
                (r'setInterval\s*\(\s*["\']',
                 '[CWE-94] Code Injection: setInterval() with string arg evaluates it as code.',
                 'ERROR', 'fallback.js.code-setinterval'),
                # Command Injection
                (r'child_process\.exec\s*\(\s*\w',
                 '[CWE-78] Command Injection: child_process.exec() with dynamic input. Use execFile().',
                 'ERROR', 'fallback.js.cmd-exec'),
                (r'child_process\.execSync\s*\(\s*\w',
                 '[CWE-78] Command Injection via execSync() with dynamic argument.',
                 'ERROR', 'fallback.js.cmd-execsync'),
                # SQL Injection
                (r'\.query\s*\(\s*`[^`]*\$\{',
                 '[CWE-89] SQL Injection via template literal in db.query().',
                 'ERROR', 'fallback.js.sqli-template-literal'),
                (r'\.query\s*\(["\'][^"\']*["\'\s]*\+',
                 '[CWE-89] SQL Injection via string concat in db.query(). Use parameterized queries.',
                 'ERROR', 'fallback.js.sqli-concat'),
                # SSTI
                (r'pug\.render\s*\(\s*\w',
                 '[CWE-94] SSTI: pug.render() with dynamic template string.',
                 'ERROR', 'fallback.js.ssti-pug'),
                # ReDoS
                (r'new\s+RegExp\s*\(\s*\w',
                 '[CWE-1333] ReDoS: RegExp from dynamic input can cause catastrophic backtracking.',
                 'WARNING', 'fallback.js.redos'),
                # NoSQL Injection
                (r'\.find\s*\(\s*\{[^}]*:\s*\w',
                 '[CWE-943] Potential NoSQL Injection in find(). Validate query operators.',
                 'WARNING', 'fallback.js.nosqli-find'),
                # XSS
                (r'\.innerHTML\s*=',
                 '[CWE-79] DOM XSS: innerHTML assignment. Use textContent or DOMPurify.',
                 'ERROR', 'fallback.js.xss-innerhtml'),
                (r'\.outerHTML\s*=',
                 '[CWE-79] DOM XSS: outerHTML assignment with unsanitized input.',
                 'ERROR', 'fallback.js.xss-outerhtml'),
                (r'\bdocument\.write\s*\(',
                 '[CWE-79] DOM XSS via document.write() with dynamic input.',
                 'ERROR', 'fallback.js.xss-document-write'),
                (r'dangerouslySetInnerHTML',
                 '[CWE-79] React dangerouslySetInnerHTML with dynamic input. Sanitize with DOMPurify first.',
                 'ERROR', 'fallback.js.xss-react-dangerous'),
                (r'window\.location\.href\s*=\s*\w',
                 '[CWE-601] Open Redirect / XSS: assigning dynamic value to location.href.',
                 'WARNING', 'fallback.js.xss-location-href'),
                # Path Traversal
                (r'__dirname\s*\+',
                 '[CWE-22] Path Traversal: __dirname concatenated with user input. Use path.resolve().',
                 'WARNING', 'fallback.js.path-dirname'),
                (r'fs\.readFile\s*\(\s*\w',
                 '[CWE-22] Path Traversal: fs.readFile() with dynamic path.',
                 'WARNING', 'fallback.js.path-readfile'),
                (r'fs\.readFileSync\s*\(\s*\w',
                 '[CWE-22] Path Traversal: fs.readFileSync() with dynamic path.',
                 'WARNING', 'fallback.js.path-readfilesync'),
                (r'res\.sendFile\s*\(\s*\w',
                 '[CWE-22] Path Traversal: Express res.sendFile() with dynamic path.',
                 'ERROR', 'fallback.js.path-sendfile'),
                # Cryptography
                (r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
                 '[CWE-327] Weak hash MD5. Use SHA-256 or stronger.',
                 'WARNING', 'fallback.js.crypto-md5'),
                (r"crypto\.createHash\s*\(\s*['\"]sha1['\"]",
                 '[CWE-327] Weak hash SHA-1. Use SHA-256 or stronger.',
                 'WARNING', 'fallback.js.crypto-sha1'),
                (r'\bMath\.random\s*\(',
                 '[CWE-338] Math.random() is not cryptographically secure. Use crypto.randomBytes().',
                 'WARNING', 'fallback.js.crypto-math-random'),
                # JWT
                (r"algorithm\s*:\s*['\"]none['\"]",
                 "[CWE-347] JWT 'none' algorithm allows token forgery. Enforce a strong algorithm.",
                 'ERROR', 'fallback.js.jwt-none-alg'),
                (r'\bjwt\.decode\s*\(',
                 '[CWE-347] jwt.decode() skips signature verification. Use jwt.verify().',
                 'ERROR', 'fallback.js.jwt-decode-noverify'),
                # Secrets
                (r'(password|secret|api_key|apiKey|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                 '[CWE-798] Hardcoded secret/credential detected. Use environment variables.',
                 'ERROR', 'fallback.js.secrets-hardcoded'),
                # SSRF
                (r'axios\.get\s*\(\s*\w',
                 '[CWE-918] Potential SSRF: axios.get() with dynamic URL. Validate and allowlist.',
                 'WARNING', 'fallback.js.ssrf-axios'),
                (r'\bfetch\s*\(\s*\w',
                 '[CWE-918] Potential SSRF: fetch() with dynamic URL. Validate and allowlist.',
                 'WARNING', 'fallback.js.ssrf-fetch'),
                # Prototype Pollution
                (r'\w+\[\w+\]\[\w+\]\s*=',
                 "[CWE-1321] Potential Prototype Pollution via bracket notation. Validate keys against '__proto__'.",
                 'WARNING', 'fallback.js.proto-pollution'),
                # Misconfiguration
                (r"cors\s*\(\s*\{\s*origin\s*:\s*['\"][*]['\"]",
                 '[CWE-942] CORS wildcard origin allows any site to read responses. Restrict origins.',
                 'WARNING', 'fallback.js.misc-cors-wildcard'),
                (r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
                 '[CWE-295] TLS certificate verification disabled. Never use in production.',
                 'ERROR', 'fallback.js.misc-tls-bypass'),
                # Logging
                (r'console\.(log|error|warn|info)\s*\(.*[Pp]assword',
                 '[CWE-532] Password/sensitive data written to console log.',
                 'WARNING', 'fallback.js.logging-sensitive'),
            ]

            java_patterns = [
                # SQL Injection
                (r'executeQuery\s*\(\s*".*"\s*\+',
                 '[CWE-89] SQL Injection via string concat in executeQuery(). Use PreparedStatement.',
                 'ERROR', 'fallback.java.sqli-executequery'),
                (r'\bexecute\s*\(\s*".*"\s*\+',
                 '[CWE-89] SQL Injection via string concat in execute(). Use PreparedStatement.',
                 'ERROR', 'fallback.java.sqli-execute'),
                (r'createQuery\s*\(\s*".*"\s*\+',
                 '[CWE-89] SQL Injection via string concat in createQuery(). Use named parameters.',
                 'ERROR', 'fallback.java.sqli-createquery'),
                (r'createQuery\s*\(\s*String\.format\s*\(',
                 '[CWE-89] SQL Injection via String.format() in Hibernate createQuery().',
                 'ERROR', 'fallback.java.sqli-hibernate-format'),
                # Command Injection
                (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*[^"]',
                 '[CWE-78] Command Injection via Runtime.exec() with dynamic argument.',
                 'ERROR', 'fallback.java.cmd-runtime-exec'),
                (r'new\s+ProcessBuilder\s*\(\s*[^"]',
                 '[CWE-78] Command Injection: ProcessBuilder with dynamic arguments.',
                 'ERROR', 'fallback.java.cmd-processbuilder'),
                # XXE
                (r'DocumentBuilderFactory\.newInstance\s*\(\)',
                 '[CWE-611] XXE: DocumentBuilderFactory without disabling external entities.',
                 'ERROR', 'fallback.java.xxe-documentbuilder'),
                (r'SAXParserFactory\.newInstance\s*\(\)',
                 '[CWE-611] XXE: SAXParserFactory without disabling external entities.',
                 'ERROR', 'fallback.java.xxe-saxparser'),
                (r'XMLInputFactory\.newInstance\s*\(\)',
                 '[CWE-611] XXE: XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES set to false.',
                 'ERROR', 'fallback.java.xxe-xmlinputfactory'),
                # Deserialization
                (r'new\s+ObjectInputStream\s*\(',
                 '[CWE-502] Unsafe Deserialization via ObjectInputStream.',
                 'ERROR', 'fallback.java.deser-objectinputstream'),
                (r'new\s+XMLDecoder\s*\(',
                 '[CWE-502] Critical: XMLDecoder deserializes arbitrary Java objects.',
                 'ERROR', 'fallback.java.deser-xmldecoder'),
                (r'new\s+XStream\s*\(\)',
                 '[CWE-502] XStream with default settings deserializes arbitrary classes.',
                 'ERROR', 'fallback.java.deser-xstream'),
                # Cryptography
                (r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)',
                 '[CWE-327] Weak hash MD5. Use SHA-256 or stronger.',
                 'WARNING', 'fallback.java.crypto-md5'),
                (r'MessageDigest\.getInstance\s*\(\s*"SHA-1"\s*\)',
                 '[CWE-327] Weak hash SHA-1. Use SHA-256 or stronger.',
                 'WARNING', 'fallback.java.crypto-sha1'),
                (r'Cipher\.getInstance\s*\(\s*"DES',
                 '[CWE-327] Weak cipher DES detected. Use AES/GCM/NoPadding.',
                 'ERROR', 'fallback.java.crypto-des'),
                (r'Cipher\.getInstance\s*\(\s*"AES/ECB',
                 '[CWE-327] AES/ECB mode is insecure (deterministic). Use AES/GCM.',
                 'ERROR', 'fallback.java.crypto-aes-ecb'),
                (r'new\s+Random\s*\(\s*\d+',
                 '[CWE-336] Predictable PRNG seed. Use SecureRandom for security-sensitive operations.',
                 'WARNING', 'fallback.java.crypto-predictable-seed'),
                # Secrets
                (r'(password|secret|passwd|pwd|api_key|apiKey|API_KEY|token|access_key|secret_key)\s*=\s*"[^"]+"',
                 '[CWE-259] Hardcoded password/secret detected. Use environment variables.',
                 'ERROR', 'fallback.java.secrets-password'),
                # Path Traversal
                (r'new\s+File\s*\([^"]*\+[^"]*\)',
                 '[CWE-22] Path Traversal: new File() with string concat. Validate and canonicalize.',
                 'ERROR', 'fallback.java.path-file'),
                (r'Paths\.get\s*\([^"]*\+[^"]*\)',
                 '[CWE-22] Path Traversal: Paths.get() with string concat.',
                 'ERROR', 'fallback.java.path-paths-get'),
                # SSRF
                (r'new\s+URL\s*\(\s*\w.*\)\.openConnection\s*\(\)',
                 '[CWE-918] Potential SSRF: URL.openConnection() with dynamic URL.',
                 'WARNING', 'fallback.java.ssrf-url-openconnection'),
                # XSS
                (r'response\.getWriter\(\)\.write\s*\(\s*\w',
                 '[CWE-79] XSS: unsanitized user input written to HTTP response. Encode output.',
                 'ERROR', 'fallback.java.xss-response-write'),
                # Log4Shell
                (r'\$\{jndi:',
                 '[CVE-2021-44228] Log4Shell pattern detected. Update Log4j >= 2.17.1.',
                 'ERROR', 'fallback.java.log4shell'),
                # Logging
                (r'log\.(info|debug|warn|error)\s*\(.*[Pp]assword',
                 '[CWE-532] Password/sensitive data written to logs.',
                 'WARNING', 'fallback.java.logging-password'),
            ]

            c_patterns = [
                # Buffer Overflows
                (r'\bgets\s*\(',
                 '[CWE-120] Critical: gets() has no bounds check. Use fgets().',
                 'ERROR', 'fallback.c.buff-gets'),
                (r'\bstrcpy\s*\(',
                 '[CWE-120] Buffer Overflow: strcpy() no size check. Use strncpy()/strlcpy().',
                 'ERROR', 'fallback.c.buff-strcpy'),
                (r'\bstrcat\s*\(',
                 '[CWE-120] Buffer Overflow: strcat() no size check. Use strncat().',
                 'ERROR', 'fallback.c.buff-strcat'),
                (r'\bsprintf\s*\(',
                 '[CWE-120] Buffer Overflow: sprintf() no size check. Use snprintf().',
                 'ERROR', 'fallback.c.buff-sprintf'),
                (r'\bvsprintf\s*\(',
                 '[CWE-120] Buffer Overflow: vsprintf() no bounds check. Use vsnprintf().',
                 'ERROR', 'fallback.c.buff-vsprintf'),
                (r'scanf\s*\(\s*"%s"',
                 '[CWE-120] Unbounded scanf("%s"). Specify a width limit or use fgets().',
                 'ERROR', 'fallback.c.buff-scanf'),
                (r'\bmemcpy\s*\(',
                 '[CWE-120] memcpy() — verify that size argument does not exceed destination buffer.',
                 'WARNING', 'fallback.c.buff-memcpy'),
                (r'\bmemmove\s*\(',
                 '[CWE-120] memmove() — verify that size does not exceed destination buffer.',
                 'WARNING', 'fallback.c.buff-memmove'),
                (r'\balloca\s*\(',
                 '[CWE-770] alloca() allocates on the stack with no overflow check. Use malloc().',
                 'WARNING', 'fallback.c.buff-alloca'),
                (r'\bstrtok\s*\(',
                 '[CWE-330] strtok() is not thread-safe. Use strtok_r() in multi-threaded contexts.',
                 'WARNING', 'fallback.c.strtok-not-reentrant'),
                # Command Injection
                (r'\bsystem\s*\(',
                 '[CWE-78] Command Injection via system(). Use execv() with sanitized argument arrays.',
                 'ERROR', 'fallback.c.cmd-system'),
                (r'\bpopen\s*\(',
                 '[CWE-78] Command Injection via popen(). Avoid passing user-controlled strings.',
                 'ERROR', 'fallback.c.cmd-popen'),
                (r'\bexeclp\s*\(',
                 '[CWE-78] Command Injection via execlp(). Avoid user-controlled path arguments.',
                 'WARNING', 'fallback.c.cmd-execlp'),
                # Format String
                (r'\bprintf\s*\(\s*\w[^,)"]*\)',
                 "[CWE-134] Format String: printf() with non-literal format. Use printf('%s', str).",
                 'ERROR', 'fallback.c.fmt-printf'),
                (r'\bfprintf\s*\(\s*\w+\s*,\s*\w[^,"]*\)',
                 '[CWE-134] Format String: fprintf() with non-literal format.',
                 'ERROR', 'fallback.c.fmt-fprintf'),
                (r'\bsyslog\s*\(\s*\w+\s*,\s*\w',
                 '[CWE-134] Format String: syslog() with non-literal format.',
                 'ERROR', 'fallback.c.fmt-syslog'),
                # Memory
                (r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',
                 '[CWE-190] Integer Overflow in malloc size expression. Use checked arithmetic or calloc().',
                 'WARNING', 'fallback.c.mem-integer-overflow-malloc'),
                # Cryptography / PRNG
                (r'\brand\s*\(',
                 '[CWE-338] rand() is not cryptographically secure. Use /dev/urandom or getrandom().',
                 'WARNING', 'fallback.c.crypto-rand'),
                (r'srand\s*\(\s*time\s*\(',
                 '[CWE-337] Predictable PRNG seed via time(). Use a cryptographic seed source.',
                 'WARNING', 'fallback.c.crypto-srand-time'),
                # Race Conditions
                (r'\btmpnam\s*\(',
                 '[CWE-377] tmpnam() is vulnerable to TOCTOU race conditions. Use mkstemp().',
                 'ERROR', 'fallback.c.race-tmpnam'),
                (r'\btempnam\s*\(',
                 '[CWE-377] tempnam() is vulnerable to TOCTOU. Use mkstemp().',
                 'ERROR', 'fallback.c.race-tempnam'),
            ]

            lang_patterns = {
                'python':     python_patterns,
                'javascript': js_patterns,
                'java':       java_patterns,
                'c':          c_patterns,
            }

            all_patterns = shared_patterns + lang_patterns.get(language, [])

            # Run all patterns, dedup by (rule_id, line_number)
            seen = set()
            for pattern, msg, sev, rule_id in all_patterns:
                flags = re.IGNORECASE if language == 'java' else 0
                for i, line in enumerate(lines):
                    if re.search(pattern, line, flags):
                        key = (rule_id, i + 1)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                'check_id': rule_id,
                                'file': file_path,
                                'line': i + 1,
                                'message': msg,
                                'severity': sev,
                                'snippet': line.strip()[:120]
                            })

            score = self._calculate_risk_score(findings, file_path)
            return findings, score

        except Exception as e:
            self.logger.error(f"Fallback scan error: {e}")
            return [], 0.0

    def _calculate_risk_score(self, findings: list, file_path: str) -> float:
        """
        Calculates a Risk Score (0.0 - 10.0) using a Severity-First approach.
        - High Risk (ERROR) triggers immediate high base score >= 7.0.
        - Cumulative increments for multiple issues.
        """
        if not findings:
            return 0.0

        SEVERITY_BASE = {'ERROR': 7.0, 'WARNING': 4.0, 'INFO': 1.0}
        SEVERITY_INC  = {'ERROR': 1.0, 'WARNING': 0.5, 'INFO': 0.1}

        max_base_score = 0.0
        severity_counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}

        for f in findings:
            s = f.get('severity', 'INFO').upper()
            if s not in severity_counts:
                s = 'INFO'
            severity_counts[s] += 1
            max_base_score = max(max_base_score, SEVERITY_BASE.get(s, 0.0))

        score = max_base_score

        # Subtract one instance of the dominant severity (don't double-count the base)
        for s in ['ERROR', 'WARNING', 'INFO']:
            if SEVERITY_BASE[s] == max_base_score and severity_counts[s] > 0:
                severity_counts[s] -= 1
                break

        score += severity_counts['ERROR']   * SEVERITY_INC['ERROR']
        score += severity_counts['WARNING'] * SEVERITY_INC['WARNING']
        score += severity_counts['INFO']    * SEVERITY_INC['INFO']

        return round(min(10.0, score), 1)


if __name__ == "__main__":
    print("Security Scanner Module Loaded.")