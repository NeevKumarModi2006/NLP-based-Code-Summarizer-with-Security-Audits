# author: Neev Modi

from tree_sitter import Node
from src.ast_parser import ASTParser

class FeatureExtractor:
    def __init__(self):
        self.parser_interface = ASTParser()

        self.queries = {
            'python': """
                (call function: (identifier) @func)
                (call function: (attribute) @func)
                (if_statement) @branch
                (for_statement) @branch
                (while_statement) @branch
                (except_clause) @branch
                (elif_clause) @branch
                (boolean_operator) @branch
            """,
            'javascript': """
                (call_expression function: (identifier) @func)
                (call_expression function: (member_expression) @func)
                (if_statement) @branch
                (for_statement) @branch
                (while_statement) @branch
                (switch_case) @branch
                (catch_clause) @branch
                (binary_expression operator: "||" @branch)
                (binary_expression operator: "&&" @branch)
            """,
            'java': """
                (method_invocation name: (identifier) @func)
                (method_invocation object: (identifier) name: (identifier) @func)
                (if_statement) @branch
                (for_statement) @branch
                (while_statement) @branch
                (catch_clause) @branch
                (switch_label) @branch
                (binary_expression operator: "||" @branch)
                (binary_expression operator: "&&" @branch)
            """,
            'c': """
                (call_expression function: (identifier) @func)
                (if_statement) @branch
                (for_statement) @branch
                (while_statement) @branch
                (case_statement) @branch
                (binary_expression operator: "||" @branch)
                (binary_expression operator: "&&" @branch)
            """
        }

        self.sources = {
            'python': {'input', 'sys.argv', 'request.args', 'request.form', 'open'},
            'javascript': {'prompt', 'process.argv', 'req.body', 'req.query'},
            'java': {'Scanner', 'System.in', 'getParameter'},
            'c': {'scanf', 'gets', 'read'}
        }
        self.sinks = {
            'python': {
                'eval', 'exec', 'os.system', 'subprocess.call', 'pickle.loads', 'subprocess.Popen',
                'cursor.execute', 'execute', 'subprocess.run', 'os.popen', 'yaml.load', 'tarfile.open'
            },
            'javascript': {
                'eval', 'setTimeout', 'child_process.exec', 'document.write', 'child_process.spawn', 'element.innerHTML'
            },
            'java': {
                'Runtime.exec', 'ProcessBuilder', 'Statement.execute', 'Runtime.loadLibrary'
            },
            'c': {
                'system', 'execl', 'popen', 'strcpy', 'strcat', 'sprintf', 'memcpy', 'gets'
            }
        }

    def extract_features(self, tree, code_str: str, language: str):
        """
        Extracts features using Tree-sitter Queries.
        """
        features = {
            'sources': [],
            'sinks': [],
            'complexity': 0
        }

        lang_obj = self.parser_interface.get_language(language)
        if not lang_obj or language not in self.queries:
            return features

        try:
            from tree_sitter import Query, QueryCursor

            query = Query(lang_obj, self.queries[language])
            cursor = QueryCursor(query)
            captures = cursor.captures(tree.root_node)

            code_bytes = code_str.encode('utf-8')

            for capture_name, nodes in captures.items():
                for node in nodes:
                    if capture_name == 'branch':
                        features['complexity'] += 1
                    elif capture_name == 'func':
                        func_name_bytes = code_bytes[node.start_byte:node.end_byte]
                        func_name = func_name_bytes.decode('utf-8', errors='ignore')

                        if func_name in self.sources.get(language, set()):
                            features['sources'].append(func_name)

                        if func_name in self.sinks.get(language, set()):
                            features['sinks'].append(func_name)
                        else:
                            pass

        except Exception as e:
            print(f"Feature extraction error: {e}")

        return features
