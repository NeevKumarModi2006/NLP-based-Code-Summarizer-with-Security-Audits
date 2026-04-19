
import json

class PromptEnricher:
    """
    this will construct a security-aware prompt for CodeT5 using AST features,
    security findings, and the raw code snippet to make CodeT5 an AST-informed summarizer.
    """

    CODE_CHAR_LIMIT = 450

    @staticmethod
    def construct_prompt(findings: list, ast_features: dict, code_snippet: str) -> str:
        """this will build the enriched prompt string from findings, AST features, and code."""

        sinks      = list(set(ast_features.get('sinks', [])))
        sources    = list(set(ast_features.get('sources', [])))
        complexity = ast_features.get('complexity', 0)

        sink_str   = ", ".join(sinks)   if sinks   else "none"
        source_str = ", ".join(sources) if sources else "none"

        ast_context = (
            f"Dangerous calls: {sink_str}. "
            f"Input sources: {source_str}. "
            f"Branch complexity: {complexity}."
        )

        if not findings:
            findings_str = "No vulnerabilities detected."
        else:
            findings_str = "; ".join(
                f"{f['severity']} - {f['message']} (line {f['line']})"
                for f in findings
            )

        code_truncated = code_snippet[:PromptEnricher.CODE_CHAR_LIMIT]

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
