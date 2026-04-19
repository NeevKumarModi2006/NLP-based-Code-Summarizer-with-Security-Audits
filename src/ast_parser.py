
import os
from tree_sitter import Language, Parser
import tree_sitter_python
import tree_sitter_java
import tree_sitter_c
import tree_sitter_javascript

class ASTParser:
    def __init__(self):
        self.languages = {
            'python': tree_sitter_python.language(),
            'java': tree_sitter_java.language(),
            'c': tree_sitter_c.language(),
            'javascript': tree_sitter_javascript.language()
        }
        self.parsers = {}
        for lang_name, lang_obj in self.languages.items():
            parser = Parser(Language(lang_obj))
            self.parsers[lang_name] = parser

    def parse(self, code: str, language: str):
        if language not in self.parsers:
            raise ValueError(f"Language {language} not supported. Supported: {list(self.parsers.keys())}")
        return self.parsers[language].parse(bytes(code, "utf8"))

    def get_language(self, language_name: str):
        if language_name not in self.languages:
             return None
        return Language(self.languages[language_name])
