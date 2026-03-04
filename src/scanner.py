# author: Neev Modi

# import subprocess
# import json
# import logging
# import math

# class Scanner:
#     def __init__(self):
#         self.logger = logging.getLogger(__name__)

#     def scan_file(self, file_path: str):
#         """
#         Runs semgrep on a single file and returns structured findings.
#         """
#         try:
#             import os
#             import sys

#             script_dir = os.path.dirname(os.path.abspath(__file__))
#             rules_path = os.path.join(script_dir, 'rules.yaml')

#             config = rules_path if os.path.exists(rules_path) else 'p/security-audit'

#             scripts_dir = os.path.dirname(sys.executable)
#             if 'Scripts' not in scripts_dir:
#                  scripts_dir = os.path.join(os.path.dirname(sys.executable), 'Scripts')

#             pysemgrep = os.path.join(scripts_dir, 'pysemgrep.exe')
#             semgrep_exe = os.path.join(scripts_dir, 'semgrep.exe')

#             executable = None
#             if os.path.exists(pysemgrep):
#                 executable = pysemgrep
#             elif os.path.exists(semgrep_exe):
#                 executable = semgrep_exe

#             if executable:
#                  cmd_str = f'"{executable}" scan --config "{config}" --json --quiet "{file_path}"'
#             else:
#                  cmd_str = f'"{sys.executable}" -m semgrep scan --config "{config}" --json "{file_path}"'

#             env = os.environ.copy()

#             paths_to_add = [
#                 r'C:\Users\Neev\AppData\Roaming\Python\Python313\Scripts',
#                 r'C:\Users\Neev\AppData\Roaming\Python\Python313\site-packages\semgrep\bin'
#             ]

#             existing_path = env.get('PATH', '')
#             for p in paths_to_add:
#                 if os.path.exists(p):
#                     existing_path = p + os.pathsep + existing_path

#             env['PATH'] = existing_path

#             result = subprocess.run(cmd_str, capture_output=True, text=True, env=env, shell=True)

#             if result.returncode != 0 and result.stderr:
#                 self.logger.warning(f"Semgrep execution warning: {result.stderr}")

#             findings = []
#             risk_score = 0.0

#             if result.returncode == 0 or result.stdout:
#                 try:
#                     output_lines = result.stdout.strip().splitlines()
#                     json_str = ""
#                     for line in reversed(output_lines):
#                         if line.strip().startswith('{') and line.strip().endswith('}'):
#                              json_str = line
#                              break

#                     if not json_str:
#                         json_str = result.stdout

#                     json_output = json.loads(json_str)
#                     findings = self._parse_semgrep_output(json_output)
#                     risk_score = self._calculate_risk_score(findings, file_path)
#                 except json.JSONDecodeError:
#                     self.logger.error("Failed to parse Semgrep JSON output.")

#             if not findings:
#                  self.logger.warning("Semgrep returned no results. Running internal AST fallback scan.")
#                  return self._fallback_scan(file_path)

#             return findings, risk_score

#         except FileNotFoundError:
#             self.logger.error("Semgrep CLI not found.")
#             return self._fallback_scan(file_path)
#         except Exception as e:
#             self.logger.error(f"Error during security scan: {str(e)}")
#             return self._fallback_scan(file_path)

#     def _fallback_scan(self, file_path: str):
#         """
#         Internal fallback scanner using AST Feature Extraction when Semgrep is unavailable.
#         """
#         try:
#             from src.ast_parser import ASTParser
#             from src.feature_extractor import FeatureExtractor
#             import os

#             findings = []

#             ext = os.path.splitext(file_path)[1].lower()
#             lang_map = {'.py': 'python', '.js': 'javascript', '.java': 'java', '.c': 'c'}
#             language = lang_map.get(ext)

#             if not language:
#                 return [], 0.0

#             with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
#                 code_content = f.read()

#             parser = ASTParser()
#             extractor = FeatureExtractor()

#             tree = parser.parse(code_content, language)
#             features = extractor.extract_features(tree, code_content, language)

#             sinks = features.get('sinks', [])

#             for sink in sinks:
#                 severity = 'ERROR' if sink == 'pickle.loads' else 'WARNING'
#                 findings.append({
#                     'check_id': f'fallback.sink.{sink}',
#                     'file': file_path,
#                     'line': 0,
#                     'message': f'Potential security sink identified: {sink}(...)',
#                     'severity': severity,
#                     'snippet': f'{sink}(...)'
#                 })

#             import re
#             check_list = []

#             if language == 'python':
#                 check_list.append({
#                     'id': 'fallback.sqli-inline',
#                     'pattern': r'\.execute\s*\([^)]*[\'\"]\s*[\+]',
#                     'msg': 'High Risk: Potential SQL Injection (inline formatting).',
#                     'sev': 'ERROR'
#                 })
#                 check_list.append({
#                     'id': 'fallback.dangerous-subprocess-shell',
#                     'pattern': r'subprocess\.Popen.*shell\s*=\s*True',
#                     'msg': 'High Risk: Execution of unsanitized user input via subprocess with shell=True.',
#                     'sev': 'ERROR'
#                 })
#                 check_list.append({
#                      'id': 'fallback.pickle',
#                      'pattern': r'pickle\.loads',
#                      'msg': 'High Risk: Unsafe deserialization detected (pickle).',
#                      'sev': 'ERROR'
#                 })
#                 check_list.append({
#                      'id': 'fallback.weak-hash-md5',
#                      'pattern': r'hashlib\.md5',
#                      'msg': 'Weak hashing algorithm (MD5) detected.',
#                      'sev': 'WARNING'
#                 })
#                 check_list.append({
#                      'id': 'fallback.hardcoded-aws',
#                      'pattern': r'AKIA[0-9A-Z]{16}',
#                      'msg': 'Critical: Hardcoded AWS Access Key detected.',
#                      'sev': 'ERROR'
#                 })
#                 check_list.append({
#                      'id': 'fallback.sqli-string',
#                      'pattern': r'[\"\']\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b.*[\"\']\s*[%+]',
#                      'msg': 'High Risk: Potential SQL Injection detected (formatted SQL string).',
#                      'sev': 'ERROR'
#                 })

#             elif language == 'javascript':
#                 check_list.append({
#                     'id': 'fallback.js-weak-hash',
#                     'pattern': r'crypto\.createHash\([\'"]md5[\'"]\)',
#                     'msg': 'Weak hashing algorithm (MD5) detected.',
#                     'sev': 'WARNING'
#                 })
#                 check_list.append({
#                     'id': 'fallback.js-path-exposure',
#                     'pattern': r'__dirname\s*\+',
#                     'msg': 'Potential Path Traversal/Information Disclosure.',
#                     'sev': 'WARNING'
#                 })

#             elif language == 'java':
#                  check_list.append({
#                     'id': 'fallback.java-sqli-inline',
#                     'pattern': r'executeQuery\s*\(\s*\".*\"\s*\+',
#                     'msg': 'Potential SQL Injection (String Concatenation).',
#                     'sev': 'ERROR'
#                  })
#                  check_list.append({
#                     'id': 'fallback.java-sqli-string',
#                     'pattern': r'[\"\']\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b.*[\"\']\s*\+',
#                     'msg': 'High Risk: Potential SQL Injection (String Concatenation in Query).',
#                     'sev': 'ERROR'
#                  })

#             elif language == 'c':
#                  check_list.append({
#                     'id': 'fallback.c-buffer-overflow-strcpy',
#                     'pattern': r'strcpy\(',
#                     'msg': 'Potential Buffer Overflow. Use strncpy instead.',
#                     'sev': 'ERROR'
#                  })
#                  check_list.append({
#                     'id': 'fallback.c-command-injection',
#                     'pattern': r'system\(',
#                     'msg': 'Command Injection Risk.',
#                     'sev': 'ERROR'
#                  })
#                  check_list.append({
#                     'id': 'fallback.c-gets',
#                     'pattern': r'gets\(',
#                     'msg': "Critical: 'gets' is unsafe and can cause buffer overflows.",
#                     'sev': 'ERROR'
#                  })

#             lines = code_content.splitlines()
#             for check in check_list:
#                 if re.search(check['pattern'], code_content, re.MULTILINE):
#                     for i, line in enumerate(lines):
#                          if re.search(check['pattern'], line):
#                              findings.append({
#                                 'check_id': check['id'],
#                                 'file': file_path,
#                                 'line': i + 1,
#                                 'message': check['msg'],
#                                 'severity': check['sev'],
#                                 'snippet': line.strip()[:100]
#                              })

#             risk_score = self._calculate_risk_score(findings, file_path)
#             return findings, risk_score

#         except Exception as e:
#             self.logger.error(f"Fallback scan failed: {e}")
#             return [], 0.0

#     def _parse_semgrep_output(self, json_output: dict):
#         parsed_findings = []
#         results = json_output.get('results', [])

#         for item in results:
#             finding = {
#                 'check_id': item.get('check_id'),
#                 'file': item.get('path'),
#                 'line': item.get('start', {}).get('line'),
#                 'message': item.get('extra', {}).get('message'),
#                 'severity': item.get('extra', {}).get('severity', 'INFO'),
#                 'snippet': item.get('extra', {}).get('lines')
#             }
#             parsed_findings.append(finding)

#         return parsed_findings

#     def _calculate_risk_score(self, findings: list, file_path: str) -> float:
#         """
#         Calculates a Risk Score (0.0 - 10.0).
#         - Weighted sum of vulnerabilities (High=3, Medium=2, Low=1)
#         - Density penalty based on line count.
#         - Cap at 10.0.
#         """
#         weights = {'ERROR': 3.0, 'WARNING': 2.0, 'INFO': 0.5}
#         total_weight = 0.0

#         for f in findings:
#             severity = f.get('severity', 'INFO')
#             weight = weights.get(severity.upper(), 1.0)
#             total_weight += weight

#         try:
#             with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
#                 line_count = sum(1 for _ in f)
#         except:
#              line_count = 100

#         if line_count == 0:
#             line_count = 1

#         density = total_weight / math.log(line_count + 1) * 5.0
#         score = min(10.0, density)
#         return round(score, 1)

# if __name__ == "__main__":
#     scanner = Scanner()
#     print("Scanner initialized. Run from main.")

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
        Falls back to internal Regex/AST scan if Semgrep fails.
        """
        try:
            env = os.environ.copy()
            appdata_path = os.environ.get('APPDATA', '')
            user_scripts = os.path.join(appdata_path, 'Python', 'Python313', 'Scripts')

            if os.path.exists(user_scripts):
                env['PATH'] = user_scripts + os.pathsep + env.get('PATH', '')

            script_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(script_dir, 'rules.yaml')
            config = rules_path if os.path.exists(rules_path) else 'p/security-audit'

            cmd = f'semgrep scan --config "{config}" --json --quiet "{file_path}"'

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, shell=True)

            findings = []
            risk_score = 0.0

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
        Internal Regex-based scanner for Python, Java, C, and JS.
        Ensures coverage even when Semgrep is unavailable.
        """
        findings = []
        try:
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {'.py': 'python', '.js': 'javascript', '.java': 'java', '.c': 'c'}
            language = lang_map.get(ext)
            if not language: return [], 0.0

            try:
                from src.ast_parser import ASTParser
                from src.feature_extractor import FeatureExtractor

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()

                parser = ASTParser()
                extractor = FeatureExtractor()
                tree = parser.parse(code_content, language)
                features = extractor.extract_features(tree, code_content, language)

                sinks = features.get('sinks', [])
                HIGH_RISK_SINKS = {
                    'eval', 'exec', 'os.system', 'pickle.loads', 'subprocess.Popen', 'subprocess.run',
                    'document.write', 'system', 'strcpy', 'memcpy', 'gets', 'yaml.load'
                }

                for sink in sinks:
                    severity = 'ERROR' if sink in HIGH_RISK_SINKS else 'WARNING'
                    findings.append({
                        'check_id': f'fallback.sink.{sink}',
                        'file': file_path,
                        'line': 0,
                        'message': f'Potential security sink identified: {sink}(...)',
                        'severity': severity,
                        'snippet': f'{sink}(...)'
                    })
            except Exception as ast_err:
                self.logger.warning(f"AST extraction failed: {ast_err}")

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()

            patterns = [
                (r'AKIA[0-9A-Z]{16}', 'Critical: Hardcoded AWS Access Key', 'ERROR'),
                (r'pickle\.loads', 'High Risk: Unsafe deserialization (pickle)', 'ERROR'),
                (r'subprocess\.Popen.*shell\s*=\s*True', 'High Risk: Command Injection via shell=True', 'ERROR'),
                (r'eval\(', 'Critical: Arbitrary code execution (eval)', 'ERROR'),
                (r'hashlib\.md5', 'Medium: Weak cryptographic hash (MD5)', 'WARNING'),
                (r'strcpy\(', 'High Risk: Potential Buffer Overflow (strcpy)', 'ERROR'),
                (r'gets\(', 'Critical: Dangerous gets() usage', 'ERROR'),
                (r'system\(', 'High Risk: System command execution', 'ERROR'),
                (r'cursor\.execute\(f[\"\']', 'High Risk: SQL Injection via f-string', 'ERROR'),
                (r'document\.write\(', 'High Risk: DOM XSS via document.write', 'ERROR'),
                (r'memcpy\(', 'High Risk: Potential Memory Corruption (memcpy)', 'ERROR')
            ]

            for pattern, msg, sev in patterns:
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        findings.append({
                            'check_id': f'fallback.{pattern[:10]}',
                            'file': file_path,
                            'line': i + 1,
                            'message': msg,
                            'severity': sev,
                            'snippet': line.strip()
                        })

            score = self._calculate_risk_score(findings, file_path)
            return findings, score
        except Exception as e:
            self.logger.error(f"Fallback scan error: {e}")
            return [], 0.0

    def _calculate_risk_score(self, findings: list, file_path: str) -> float:
        """
        Calculates a Risk Score (0.0 - 10.0) using a Severity-First approach.
        - High Risk (ERROR) triggers immediate high score (>= 7.0).
        - Cumulative score for multiple issues.
        """
        if not findings:
            return 0.0

        SEVERITY_BASE = {'ERROR': 7.0, 'WARNING': 4.0, 'INFO': 1.0}
        SEVERITY_INC = {'ERROR': 1.0, 'WARNING': 0.5, 'INFO': 0.1}

        max_base_score = 0.0
        severity_counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}

        for f in findings:
            s = f.get('severity', 'INFO').upper()
            if s not in severity_counts:
                s = 'INFO'
            severity_counts[s] += 1
            max_base_score = max(max_base_score, SEVERITY_BASE.get(s, 0.0))

        score = max_base_score

        primary_severity = None
        for s in ['ERROR', 'WARNING', 'INFO']:
             if SEVERITY_BASE[s] == max_base_score and severity_counts[s] > 0:
                 primary_severity = s
                 break

        if primary_severity:
            severity_counts[primary_severity] -= 1

        score += (severity_counts['ERROR'] * SEVERITY_INC['ERROR'])
        score += (severity_counts['WARNING'] * SEVERITY_INC['WARNING'])
        score += (severity_counts['INFO'] * SEVERITY_INC['INFO'])

        return round(min(10.0, score), 1)

if __name__ == "__main__":
    print("Security Scanner Module Loaded.")