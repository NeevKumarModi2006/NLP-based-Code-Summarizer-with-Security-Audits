import json

class PromptEnricher:
    CODE_CHAR_LIMIT = 450

    @staticmethod
    def construct_prompt(findings: list, ast_features: dict, code_snippet: str) -> str:
        """this will construct the enriched prompt string."""

        sinks      = list(set(ast_features.get('sinks', [])))
        sources    = list(set(ast_features.get('sources', [])))
        complexity = ast_features.get('complexity', 0)

        sink_section   = f"sinks={', '.join(sinks)} | " if sinks else ""
        source_section = f"sources={', '.join(sources)} | " if sources else ""

        if not findings:
            # For entirely safe chunks, strip out all prompt attributes except code.
            # CodeT5 occasionally hallucinates buzzwords (e.g. nagios, malformed)
            # if we leave empty attribute headers. Giving it only the code forces
            # it to explain just the function's structural logic.
            return code_snippet[:PromptEnricher.CODE_CHAR_LIMIT]
        else:
            findings_str = "; ".join(
                f"{f['severity']} - {f['message']} (line {f['line']})"
                for f in findings
            )
            header = (
                f"/* "
                f"sinks={', '.join(sinks) if sinks else 'none'} | "
                f"sources={', '.join(sources) if sources else 'none'} | "
                f"complexity={complexity} | "
                f"security_findings={findings_str}"
                f" */"
            )

        code_truncated = code_snippet[:PromptEnricher.CODE_CHAR_LIMIT]
        prompt = f"{header}\n{code_truncated}"

        return prompt
