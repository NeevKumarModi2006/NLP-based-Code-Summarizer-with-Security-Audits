
import json

class PromptEnricher:
    """
    Constructs a security-aware prompt for CodeT5.

    The prompt feeds three sources of structured information into the model:
      1. AST-extracted features  - dangerous function calls (sinks), input
         sources, and cyclomatic complexity derived from the parsed syntax tree.
      2. Security findings       - vulnerability messages from Semgrep / fallback scanner.
      3. Raw code snippet        - truncated to keep total prompt under 512 tokens.

    This makes CodeT5 an *AST-informed* summarizer: its output reflects the
    structural properties of the code, not just surface-level text patterns.
    """

    # Token budget: CodeT5 accepts 512 tokens max.
    # We allocate ~200 chars for the feature/findings header, rest for code.
    CODE_CHAR_LIMIT = 450

    @staticmethod
    def construct_prompt(findings: list, ast_features: dict, code_snippet: str) -> str:
        """
        Build the enriched prompt string.

        Parameters
        ----------
        findings     : list of dicts with 'message', 'severity', 'line'
        ast_features : dict with keys 'sources', 'sinks', 'complexity'
        code_snippet : raw source code string
        """

        # 1. AST-derived context 
        sinks      = list(set(ast_features.get('sinks', [])))
        sources    = list(set(ast_features.get('sources', [])))
        complexity = ast_features.get('complexity', 0)

        # Format as natural-language facts the model can reason about.
        sink_str   = ", ".join(sinks)   if sinks   else "none"
        source_str = ", ".join(sources) if sources else "none"

        ast_context = (
            f"Dangerous calls: {sink_str}. "
            f"Input sources: {source_str}. "
            f"Branch complexity: {complexity}."
        )

        # 2. Security findings 
        if not findings:
            findings_str = "No vulnerabilities detected."
        else:
            findings_str = "; ".join(
                f"{f['severity']} - {f['message']} (line {f['line']})"
                for f in findings
            )

        #  3. Code snippet (truncated)
        code_truncated = code_snippet[:PromptEnricher.CODE_CHAR_LIMIT]

        # 4. Assemble prompt 
        # CodeT5 expects the code section to follow a "Code:\n" line break —
        # that matches its CodeSearchNet training format.
        # AST features + findings go in a compact structured header BEFORE the
        # code block so the model can reason about them when summarising.
        #
        # Final shape:
        #   Summarize: [sinks=...] [sources=...] [complexity=N] [findings=...]
        #   Code:
        #   <source code>
        #
        header = (
            f"/* "
            f"sinks={sink_str} | "
            f"sources={source_str} | "
            f"complexity={complexity} | "
            f"findings={findings_str}"
            f" */"
        )

        prompt = f"{header}\n{code_truncated}"

        return prompt
